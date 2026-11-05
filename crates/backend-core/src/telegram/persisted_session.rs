use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        Mutex, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use serde::{Deserialize, Serialize};

use grammers_session::{
    Session, SessionData,
    types::{ChannelState, DcOption, PeerId, PeerInfo, UpdateState, UpdatesState},
};

use crate::{CoreError, Result, accounts::SessionCipher};

#[derive(Serialize, Deserialize)]
struct SessionSnapshot {
    home_dc: i32,
    dc_options: HashMap<i32, DcOption>,
    peer_infos: HashMap<PeerId, PeerInfo>,
    updates_state: UpdatesState,
}

impl From<&SessionData> for SessionSnapshot {
    fn from(data: &SessionData) -> Self {
        Self {
            home_dc: data.home_dc,
            dc_options: data.dc_options.clone(),
            peer_infos: data.peer_infos.clone(),
            updates_state: data.updates_state.clone(),
        }
    }
}

impl From<SessionSnapshot> for SessionData {
    fn from(data: SessionSnapshot) -> Self {
        Self {
            home_dc: data.home_dc,
            dc_options: data.dc_options,
            peer_infos: data.peer_infos,
            updates_state: data.updates_state,
        }
    }
}

pub fn session_data_from_slice(bytes: &[u8]) -> Result<SessionData> {
    serde_json::from_slice::<SessionSnapshot>(bytes)
        .map(SessionData::from)
        .map_err(|_| CoreError::Unauthorized)
}

/// A synchronous Grammers session that persists only encrypted snapshots.
pub struct PersistedSession {
    data: Mutex<SessionData>,
    cipher: SessionCipher,
    location: RwLock<Option<PathBuf>>,
    persistence_lock: Mutex<()>,
    dirty: AtomicBool,
    revision: AtomicU64,
    persistence_failed: AtomicBool,
}

impl PersistedSession {
    pub fn new(cipher: SessionCipher, data: Option<SessionData>) -> Self {
        Self {
            data: Mutex::new(data.unwrap_or_default()),
            cipher,
            location: RwLock::new(None),
            persistence_lock: Mutex::new(()),
            dirty: AtomicBool::new(false),
            revision: AtomicU64::new(0),
            persistence_failed: AtomicBool::new(false),
        }
    }

    pub fn bind(&self, account_dir: &Path) -> Result<()> {
        *self.location.write().expect("session location") = Some(account_dir.to_path_buf());
        self.persistence_failed.store(false, Ordering::Release);
        self.dirty.store(true, Ordering::Release);
        self.persist()
    }

    pub fn export(&self) -> Result<Vec<u8>> {
        if self.persistence_failed.load(Ordering::Acquire) {
            return Err(CoreError::Unavailable(
                "encrypted session persistence previously failed".to_string(),
            ));
        }
        self.flush()?;
        self.serialize()
    }

    pub fn flush(&self) -> Result<()> {
        self.persist()
    }

    fn mark_dirty(&self) {
        self.revision.fetch_add(1, Ordering::AcqRel);
        self.dirty.store(true, Ordering::Release);
    }

    fn serialize(&self) -> Result<Vec<u8>> {
        let snapshot = SessionSnapshot::from(&*self.data.lock().expect("session data"));
        serde_json::to_vec(&snapshot).map_err(|error| CoreError::Internal(error.to_string()))
    }

    fn persist(&self) -> Result<()> {
        let location = self.location.read().expect("session location").clone();
        let Some(location) = location else {
            return Ok(());
        };
        let _persistence = self.persistence_lock.lock().expect("session persistence");
        if !self.dirty.load(Ordering::Acquire) {
            return Ok(());
        }
        let revision = self.revision.load(Ordering::Acquire);
        let bytes = self.serialize()?;
        if let Err(error) = self.cipher.save_blocking(&location, &bytes) {
            self.persistence_failed.store(true, Ordering::Release);
            tracing::warn!("encrypted Telegram session persistence failed");
            return Err(error);
        }
        if self.revision.load(Ordering::Acquire) == revision {
            self.dirty.store(false, Ordering::Release);
        }
        self.persistence_failed.store(false, Ordering::Release);
        Ok(())
    }

    fn persist_infallible(&self) {
        let _ = self.persist();
    }
}

impl Session for PersistedSession {
    fn home_dc_id(&self) -> i32 {
        self.data.lock().expect("session data").home_dc
    }

    fn set_home_dc_id(&self, dc_id: i32) {
        self.data.lock().expect("session data").home_dc = dc_id;
        self.mark_dirty();
        self.persist_infallible();
    }

    fn dc_option(&self, dc_id: i32) -> Option<DcOption> {
        self.data
            .lock()
            .expect("session data")
            .dc_options
            .get(&dc_id)
            .cloned()
    }

    fn set_dc_option(&self, dc_option: &DcOption) {
        self.data
            .lock()
            .expect("session data")
            .dc_options
            .insert(dc_option.id, dc_option.clone());
        self.mark_dirty();
        self.persist_infallible();
    }

    fn peer(&self, peer: PeerId) -> Option<PeerInfo> {
        self.data
            .lock()
            .expect("session data")
            .peer_infos
            .get(&peer)
            .cloned()
    }

    fn cache_peer(&self, peer: &PeerInfo) {
        self.data
            .lock()
            .expect("session data")
            .peer_infos
            .insert(peer.id(), peer.clone());
        self.mark_dirty();
    }

    fn updates_state(&self) -> UpdatesState {
        self.data
            .lock()
            .expect("session data")
            .updates_state
            .clone()
    }

    fn set_update_state(&self, update: UpdateState) {
        {
            let mut data = self.data.lock().expect("session data");
            match update {
                UpdateState::All(state) => data.updates_state = state,
                UpdateState::Primary { pts, date, seq } => {
                    data.updates_state.pts = pts;
                    data.updates_state.date = date;
                    data.updates_state.seq = seq;
                }
                UpdateState::Secondary { qts } => data.updates_state.qts = qts,
                UpdateState::Channel { id, pts } => {
                    data.updates_state
                        .channels
                        .retain(|channel| channel.id != id);
                    data.updates_state.channels.push(ChannelState { id, pts });
                }
            }
        }
        self.mark_dirty();
    }
}
