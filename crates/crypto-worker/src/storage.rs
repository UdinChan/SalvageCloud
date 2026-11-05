//! Account-scoped IndexedDB persistence for encrypted vaults and nonsecret continuation journals.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use futures_channel::oneshot;
use js_sys::{Array, Reflect, Uint8Array};
use salvage_tdenc2::Header;
use wasm_bindgen::{JsCast, JsValue, closure::Closure};
use web_sys::{
    Event, IdbDatabase, IdbFactory, IdbObjectStore, IdbOpenDbRequest, IdbRequest, IdbTransaction,
    IdbTransactionMode, IdbVersionChangeEvent,
};

use crate::protocol::{ContinuationJournal, WorkerError, WorkerResult};

const DATABASE_NAME: &str = "salvage-cloud-crypto";
const DATABASE_VERSION: u32 = 1;
const VAULT_STORE: &str = "vaults";
const JOURNAL_STORE: &str = "journals";

fn js_error(context: &str) -> WorkerError {
    WorkerError::new(context.to_owned())
}

fn indexed_db() -> WorkerResult<IdbFactory> {
    Reflect::get(&js_sys::global(), &JsValue::from_str("indexedDB"))
        .map_err(|_| js_error("IndexedDB is unavailable"))?
        .dyn_into::<IdbFactory>()
        .map_err(|_| js_error("IndexedDB is unavailable in this browser context"))
}

async fn await_request(request: &IdbRequest) -> WorkerResult<JsValue> {
    let (sender, receiver) = oneshot::channel();
    let sender = std::rc::Rc::new(std::cell::RefCell::new(Some(sender)));
    let success_sender = sender.clone();
    let failure_sender = sender.clone();
    let success = Closure::wrap(Box::new(move |event: Event| {
        if let Some(sender) = success_sender.borrow_mut().take() {
            let result = event
                .current_target()
                .ok_or_else(|| js_error("IndexedDB request has no event target"))
                .and_then(|target| {
                    target
                        .dyn_into::<IdbRequest>()
                        .map_err(|_| js_error("IndexedDB request has an invalid event target"))
                })
                .and_then(|request| {
                    request
                        .result()
                        .map_err(|_| js_error("IndexedDB request failed"))
                });
            let _ = sender.send(result);
        }
    }) as Box<dyn FnMut(Event)>);
    let failure = Closure::wrap(Box::new(move |_event: Event| {
        if let Some(sender) = failure_sender.borrow_mut().take() {
            let _ = sender.send(Err(js_error("IndexedDB request failed")));
        }
    }) as Box<dyn FnMut(Event)>);
    // Callbacks do not retain their request, so the JS request and handlers can be collected.
    request.set_onsuccess(Some(success.as_ref().unchecked_ref()));
    request.set_onerror(Some(failure.as_ref().unchecked_ref()));
    success.forget();
    failure.forget();
    receiver
        .await
        .map_err(|_| js_error("IndexedDB request was cancelled"))?
}

async fn await_transaction(transaction: &IdbTransaction) -> WorkerResult<()> {
    let (sender, receiver) = oneshot::channel();
    let sender = std::rc::Rc::new(std::cell::RefCell::new(Some(sender)));
    let complete_sender = sender.clone();
    let failure_sender = sender.clone();
    let complete = Closure::wrap(Box::new(move |_event: Event| {
        if let Some(sender) = complete_sender.borrow_mut().take() {
            let _ = sender.send(Ok(()));
        }
    }) as Box<dyn FnMut(Event)>);
    let failure = Closure::wrap(Box::new(move |_event: Event| {
        if let Some(sender) = failure_sender.borrow_mut().take() {
            let _ = sender.send(Err(js_error("IndexedDB transaction failed")));
        }
    }) as Box<dyn FnMut(Event)>);
    transaction.set_oncomplete(Some(complete.as_ref().unchecked_ref()));
    transaction.set_onerror(Some(failure.as_ref().unchecked_ref()));
    transaction.set_onabort(Some(failure.as_ref().unchecked_ref()));
    complete.forget();
    failure.forget();
    receiver
        .await
        .map_err(|_| js_error("IndexedDB transaction was cancelled"))?
}

async fn open_database() -> WorkerResult<IdbDatabase> {
    let request = indexed_db()?
        .open_with_u32(DATABASE_NAME, DATABASE_VERSION)
        .map_err(|_| js_error("could not open the encrypted-worker IndexedDB database"))?;
    let upgrade = Closure::wrap(Box::new(move |event: IdbVersionChangeEvent| {
        if event.old_version() >= 1.0 {
            return;
        }
        let Some(target) = event.current_target() else {
            return;
        };
        let request: &IdbOpenDbRequest = target.unchecked_ref();
        if let Ok(database) = request.result()
            && let Ok(database) = database.dyn_into::<IdbDatabase>()
        {
            let _ = database.create_object_store(VAULT_STORE);
            let _ = database.create_object_store(JOURNAL_STORE);
        }
    }) as Box<dyn FnMut(IdbVersionChangeEvent)>);
    request.set_onupgradeneeded(Some(upgrade.as_ref().unchecked_ref()));
    upgrade.forget();
    let value = await_request(request.as_ref()).await?;
    value
        .dyn_into::<IdbDatabase>()
        .map_err(|_| js_error("IndexedDB returned an invalid database handle"))
}

fn store(
    database: &IdbDatabase,
    name: &str,
    mode: IdbTransactionMode,
) -> WorkerResult<(IdbTransaction, IdbObjectStore)> {
    let transaction = database
        .transaction_with_str_and_mode(name, mode)
        .map_err(|_| js_error("could not start an IndexedDB transaction"))?;
    let store = transaction
        .object_store(name)
        .map_err(|_| js_error("could not open an IndexedDB object store"))?;
    Ok((transaction, store))
}

fn vault_key(account_id: &str) -> WorkerResult<String> {
    if account_id.is_empty() {
        return Err(WorkerError::new("account ID must not be empty"));
    }
    Ok(format!("vault:{account_id}"))
}

fn journal_key(account_id: &str, original_id: &str) -> WorkerResult<String> {
    if account_id.is_empty() || original_id.is_empty() {
        return Err(WorkerError::new(
            "journal account and original IDs must not be empty",
        ));
    }
    Ok(format!(
        "journal:{}:{account_id}:{original_id}",
        account_id.len()
    ))
}

pub async fn store_vault_container(account_id: &str, container: &[u8]) -> WorkerResult<()> {
    let key = vault_key(account_id)?;
    let database = open_database().await?;
    let (transaction, store) = store(&database, VAULT_STORE, IdbTransactionMode::Readwrite)?;
    let value = Uint8Array::from(container);
    let request = store
        .put_with_key(value.as_ref(), &JsValue::from_str(&key))
        .map_err(|_| js_error("could not persist the encrypted vault"))?;
    await_request(&request).await?;
    await_transaction(&transaction).await?;
    database.close();
    Ok(())
}

pub async fn load_vault_container(account_id: &str) -> WorkerResult<Option<Vec<u8>>> {
    let key = vault_key(account_id)?;
    let database = open_database().await?;
    let (_transaction, store) = store(&database, VAULT_STORE, IdbTransactionMode::Readonly)?;
    let request = store
        .get(&JsValue::from_str(&key))
        .map_err(|_| js_error("could not read the encrypted vault"))?;
    let value = await_request(&request).await?;
    database.close();
    if value.is_undefined() || value.is_null() {
        return Ok(None);
    }
    let bytes = value
        .dyn_into::<Uint8Array>()
        .map_err(|_| js_error("stored vault value is not an encrypted byte container"))?;
    Ok(Some(bytes.to_vec()))
}

pub async fn delete_vault_container(account_id: &str) -> WorkerResult<()> {
    let key = vault_key(account_id)?;
    let database = open_database().await?;
    let (transaction, store) = store(&database, VAULT_STORE, IdbTransactionMode::Readwrite)?;
    let request = store
        .delete(&JsValue::from_str(&key))
        .map_err(|_| js_error("could not delete the encrypted vault"))?;
    await_request(&request).await?;
    await_transaction(&transaction).await?;
    database.close();
    Ok(())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_journal(journal: &ContinuationJournal) -> WorkerResult<()> {
    journal_key(&journal.account_id, &journal.original_id)?;
    if journal.remote_id.is_empty() {
        return Err(WorkerError::new("journal remote ID must not be empty"));
    }
    let header = BASE64
        .decode(&journal.complete_header)
        .map_err(|_| WorkerError::new("journal complete header is not valid base64"))?;
    let header = Header::parse(&header)?;
    if journal.next_offset > header.expected_ciphertext_len()? {
        return Err(WorkerError::new(
            "journal next offset exceeds the complete ciphertext length",
        ));
    }
    if journal
        .source_sha256
        .as_deref()
        .is_some_and(|value| !valid_digest(value))
        || journal
            .staged_ciphertext_sha256
            .as_deref()
            .is_some_and(|value| !valid_digest(value))
    {
        return Err(WorkerError::new("journal source hash is not SHA-256 hex"));
    }
    Ok(())
}

pub async fn save_journal(journal: &ContinuationJournal) -> WorkerResult<()> {
    validate_journal(journal)?;
    let key = journal_key(&journal.account_id, &journal.original_id)?;
    let value = serde_wasm_bindgen::to_value(journal)
        .map_err(|_| js_error("could not serialize the continuation journal"))?;
    let database = open_database().await?;
    let (transaction, store) = store(&database, JOURNAL_STORE, IdbTransactionMode::Readwrite)?;
    let request = store
        .put_with_key(&value, &JsValue::from_str(&key))
        .map_err(|_| js_error("could not persist the continuation journal"))?;
    await_request(&request).await?;
    await_transaction(&transaction).await?;
    database.close();
    Ok(())
}

pub async fn load_journal(
    account_id: &str,
    original_id: &str,
) -> WorkerResult<Option<ContinuationJournal>> {
    let key = journal_key(account_id, original_id)?;
    let database = open_database().await?;
    let (_transaction, store) = store(&database, JOURNAL_STORE, IdbTransactionMode::Readonly)?;
    let request = store
        .get(&JsValue::from_str(&key))
        .map_err(|_| js_error("could not read the continuation journal"))?;
    let value = await_request(&request).await?;
    database.close();
    if value.is_undefined() || value.is_null() {
        return Ok(None);
    }
    let journal: ContinuationJournal = serde_wasm_bindgen::from_value(value)
        .map_err(|_| js_error("stored continuation journal is invalid"))?;
    if journal.account_id != account_id || journal.original_id != original_id {
        return Err(js_error(
            "stored continuation journal is account-mismatched",
        ));
    }
    validate_journal(&journal)?;
    Ok(Some(journal))
}

pub async fn list_journals(account_id: &str) -> WorkerResult<Vec<ContinuationJournal>> {
    if account_id.is_empty() {
        return Err(WorkerError::new("account ID must not be empty"));
    }
    let database = open_database().await?;
    let (_transaction, store) = store(&database, JOURNAL_STORE, IdbTransactionMode::Readonly)?;
    let request = store
        .get_all()
        .map_err(|_| js_error("could not list continuation journals"))?;
    let value = await_request(&request).await?;
    database.close();
    let values = value
        .dyn_into::<Array>()
        .map_err(|_| js_error("IndexedDB returned an invalid journal list"))?;
    let mut journals = Vec::new();
    for value in values.iter() {
        let journal: ContinuationJournal = serde_wasm_bindgen::from_value(value)
            .map_err(|_| js_error("stored continuation journal is invalid"))?;
        if journal.account_id == account_id {
            validate_journal(&journal)?;
            journals.push(journal);
        }
    }
    Ok(journals)
}

pub async fn delete_journal(account_id: &str, original_id: &str) -> WorkerResult<()> {
    let key = journal_key(account_id, original_id)?;
    let database = open_database().await?;
    let (transaction, store) = store(&database, JOURNAL_STORE, IdbTransactionMode::Readwrite)?;
    let request = store
        .delete(&JsValue::from_str(&key))
        .map_err(|_| js_error("could not delete the continuation journal"))?;
    await_request(&request).await?;
    await_transaction(&transaction).await?;
    database.close();
    Ok(())
}
