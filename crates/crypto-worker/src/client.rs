//! Main-page client for the Dedicated Worker. It does not perform cryptography itself.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;

use futures_channel::oneshot;
use js_sys::Reflect;
use wasm_bindgen::{JsCast, JsValue, closure::Closure};
use web_sys::{Event, File, MessageEvent, Worker, WorkerOptions, WorkerType};
use zeroize::Zeroizing;

use crate::protocol::{
    Command, JobRequest, JobResponse, JobResult, WORKER_READY_MESSAGE, WorkerError, WorkerResult,
};

pub struct JobSuccess {
    pub result: JobResult,
    /// Present only for `JobResult::Downloaded`; already authenticated and safe to download.
    pub file: Option<File>,
}

type Pending = HashMap<String, oneshot::Sender<WorkerResult<JobSuccess>>>;

/// A cloneable handle sharing pending-job correlation for one module Worker.
#[derive(Clone)]
pub struct WorkerClient {
    worker: Worker,
    pending: Rc<RefCell<Pending>>,
    ready: Rc<Cell<bool>>,
    queued: Rc<RefCell<Vec<Zeroizing<String>>>>,
}

impl WorkerClient {
    pub fn new(url: &str) -> WorkerResult<Self> {
        let options = WorkerOptions::new();
        options.set_type(WorkerType::Module);
        let worker = Worker::new_with_options(url, &options)
            .map_err(|_| WorkerError::new("could not start the encryption Worker"))?;
        let pending = Rc::new(RefCell::new(Pending::new()));
        let ready = Rc::new(Cell::new(false));
        let queued = Rc::new(RefCell::new(Vec::<Zeroizing<String>>::new()));
        let message_pending = pending.clone();
        let message_ready = ready.clone();
        let message_queued = queued.clone();
        let message_worker = worker.clone();
        let onmessage = Closure::wrap(Box::new(move |event: MessageEvent| {
            let data = event.data();
            if data.as_string().as_deref() == Some(WORKER_READY_MESSAGE) {
                message_ready.set(true);
                let queued: Vec<_> = message_queued.borrow_mut().drain(..).collect();
                for raw in queued {
                    if message_worker
                        .post_message(&JsValue::from_str(&raw))
                        .is_err()
                    {
                        fail_all(&message_pending, "could not send the Worker request");
                        return;
                    }
                }
                return;
            }
            let parsed = if let Some(raw) = data.as_string() {
                serde_json::from_str::<JobResponse>(&raw)
                    .map_err(|_| WorkerError::new("Worker returned invalid JSON"))
            } else {
                serde_wasm_bindgen::from_value::<JobResponse>(data.clone())
                    .map_err(|_| WorkerError::new("Worker returned an invalid response"))
            };
            let response = match parsed {
                Ok(response) => response,
                Err(error) => {
                    fail_all(&message_pending, &error.to_string());
                    return;
                }
            };
            let sender = message_pending.borrow_mut().remove(&response.job_id);
            if let Some(sender) = sender {
                let outcome = if response.ok {
                    response.result.map_or_else(
                        || Err(WorkerError::new("Worker success response has no result")),
                        |result| {
                            let file = Reflect::get(&data, &JsValue::from_str("file"))
                                .ok()
                                .filter(|value| !value.is_undefined() && !value.is_null())
                                .map(|value| {
                                    value.dyn_into::<File>().map_err(|_| {
                                        WorkerError::new("Worker returned an invalid File")
                                    })
                                })
                                .transpose()?;
                            Ok(JobSuccess { result, file })
                        },
                    )
                } else {
                    Err(WorkerError::new(
                        response
                            .error
                            .unwrap_or_else(|| "Worker job failed".to_owned()),
                    ))
                };
                let _ = sender.send(outcome);
            }
        }) as Box<dyn FnMut(MessageEvent)>);
        worker.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
        onmessage.forget();

        let error_pending = pending.clone();
        let error_queued = queued.clone();
        let onerror = Closure::wrap(Box::new(move |_event: Event| {
            error_queued.borrow_mut().clear();
            fail_all(&error_pending, "encryption Worker failed");
        }) as Box<dyn FnMut(Event)>);
        worker.set_onerror(Some(onerror.as_ref().unchecked_ref()));
        onerror.forget();

        let message_error_pending = pending.clone();
        let message_error_queued = queued.clone();
        let onmessageerror = Closure::wrap(Box::new(move |_event: Event| {
            message_error_queued.borrow_mut().clear();
            fail_all(
                &message_error_pending,
                "encryption Worker message could not be decoded",
            );
        }) as Box<dyn FnMut(Event)>);
        worker.set_onmessageerror(Some(onmessageerror.as_ref().unchecked_ref()));
        onmessageerror.forget();
        Ok(Self {
            worker,
            pending,
            ready,
            queued,
        })
    }

    pub fn new_job_id() -> WorkerResult<String> {
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes)
            .map_err(|_| WorkerError::new("secure browser randomness is unavailable"))?;
        let mut id = String::with_capacity(32);
        for byte in bytes {
            use std::fmt::Write as _;
            let _ = write!(id, "{byte:02x}");
        }
        Ok(id)
    }

    pub async fn request(&self, command: Command) -> WorkerResult<JobSuccess> {
        self.request_with_id(Self::new_job_id()?, command).await
    }

    /// Uses a caller-selected ID so long-lived continuation ownership can be cancelled explicitly.
    pub async fn request_with_id(
        &self,
        job_id: String,
        command: Command,
    ) -> WorkerResult<JobSuccess> {
        if job_id.is_empty() {
            return Err(WorkerError::new("job ID must not be empty"));
        }
        if self.pending.borrow().contains_key(&job_id) {
            return Err(WorkerError::new("job ID is already active"));
        }
        let request = JobRequest {
            job_id: job_id.clone(),
            command,
        };
        let raw = Zeroizing::new(
            serde_json::to_string(&request)
                .map_err(|_| WorkerError::new("could not serialize Worker request"))?,
        );
        let (sender, receiver) = oneshot::channel();
        self.pending.borrow_mut().insert(job_id.clone(), sender);
        if self.ready.get() {
            if self.worker.post_message(&JsValue::from_str(&raw)).is_err() {
                self.pending.borrow_mut().remove(&job_id);
                return Err(WorkerError::new("could not send the Worker request"));
            }
        } else {
            self.queued.borrow_mut().push(raw);
        }
        receiver
            .await
            .map_err(|_| WorkerError::new("Worker job was terminated"))?
    }

    /// Termination is the hard cancellation boundary for synchronous Argon2/decryption work.
    /// Normal cancellation should be requested first so OPFS cleanup can finish.
    pub fn terminate(&self) {
        self.worker.terminate();
        self.queued.borrow_mut().clear();
        fail_all(&self.pending, "encryption Worker was terminated");
    }
}

fn fail_all(pending: &Rc<RefCell<Pending>>, message: &str) {
    let senders: Vec<_> = pending
        .borrow_mut()
        .drain()
        .map(|(_, sender)| sender)
        .collect();
    for sender in senders {
        let _ = sender.send(Err(WorkerError::new(message.to_owned())));
    }
}
