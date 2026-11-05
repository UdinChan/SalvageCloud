use std::path::PathBuf;

use grammers_session::{
    Session,
    types::{PeerAuth, PeerId, PeerInfo, UpdateState},
};
use salvage_backend_core::{
    accounts::{SessionCipher, session_store::session_path},
    telegram::persisted_session::{PersistedSession, session_data_from_slice},
};

fn main() {
    if let Err(error) = run() {
        eprintln!("Telegram session E2E failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let temporary =
        std::env::temp_dir().join(format!("salvage-session-e2e-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&temporary).map_err(|error| error.to_string())?;
    let result = run_storage_journey(&temporary);
    let _ = std::fs::remove_dir_all(&temporary);
    result
}

fn run_storage_journey(account_dir: &PathBuf) -> Result<(), String> {
    let cipher = SessionCipher::from_hex(&"11".repeat(32)).map_err(|error| error.to_string())?;
    let session = PersistedSession::new(cipher.clone(), None);
    session
        .bind(account_dir)
        .map_err(|error| error.to_string())?;
    let path = session_path(account_dir);
    let initial = std::fs::read(&path).map_err(|error| error.to_string())?;

    for id in 1..=256_i64 {
        session.cache_peer(&PeerInfo::User {
            id,
            auth: Some(PeerAuth::from_hash(id.wrapping_mul(17))),
            bot: Some(false),
            is_self: None,
        });
    }
    session.set_update_state(UpdateState::Primary {
        pts: 41,
        date: 42,
        seq: 43,
    });
    let during_catch_up = std::fs::read(&path).map_err(|error| error.to_string())?;
    if during_catch_up != initial {
        return Err("dialog catch-up synchronously rewrote the encrypted session".to_string());
    }

    let exported = session.export().map_err(|error| error.to_string())?;
    let persisted = std::fs::read(&path).map_err(|error| error.to_string())?;
    if persisted == initial {
        return Err("session export did not flush the completed catch-up".to_string());
    }
    let decrypted = cipher.open(&persisted).map_err(|error| error.to_string())?;
    if decrypted.as_slice() != exported {
        return Err("persisted and exported session snapshots differ".to_string());
    }
    if persisted
        .windows(b"peer_infos".len())
        .any(|window| window == b"peer_infos")
    {
        return Err("session plaintext field names reached storage".to_string());
    }

    let restored_data = session_data_from_slice(&exported).map_err(|error| error.to_string())?;
    let restored = PersistedSession::new(cipher, Some(restored_data));
    for id in [1_i64, 128, 256] {
        let peer = restored
            .peer(PeerId::user(id))
            .ok_or_else(|| format!("restored session lost peer {id}"))?;
        if peer.auth().hash() != id.wrapping_mul(17) {
            return Err(format!("restored peer {id} has the wrong access hash"));
        }
    }
    if restored.updates_state().pts != 41 || restored.updates_state().seq != 43 {
        return Err("restored update state differs".to_string());
    }

    println!("{{\"status\":\"ok\",\"deferred_peer_writes\":256,\"restore\":true}}");
    Ok(())
}
