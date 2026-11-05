use std::{
    io::Cursor,
    path::{Path, PathBuf},
};

use salvage_tdenc2::{
    Credential, EncryptionSession, ProtectedMetadata, SessionRandomness, SlotRandomness,
    decrypt_reader,
    recovery::{open_recovery, seal_recovery},
    vault::{open_vault, seal_vault},
};

fn main() {
    if let Err(error) = run() {
        eprintln!("TDENC2 E2E failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let vectors = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("fixture directory argument required")?;
    let temporary =
        std::env::temp_dir().join(format!("salvage-tdenc2-e2e-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&temporary).map_err(|error| error.to_string())?;
    let result = run_journeys(&vectors, &temporary);
    let _ = std::fs::remove_dir_all(&temporary);
    result
}

fn run_journeys(vectors: &Path, temporary: &Path) -> Result<(), String> {
    let plaintext: Vec<u8> = (0..1_048_593).map(|index| (index % 251) as u8).collect();
    let master = [7_u8; 32];
    for (sync_path, golden) in [
        (None, "v3.9.8-envelope.tdenc"),
        (Some("docs/2026/fixed-answer.bin"), "current-envelope.tdenc"),
    ] {
        let mut metadata = ProtectedMetadata::new("fixed-answer.bin", "application/octet-stream");
        if let Some(path) = sync_path {
            metadata = metadata.with_sync_path(path);
        }
        let session = EncryptionSession::new_with_randomness(
            plaintext.len() as u64,
            Some(metadata.clone()),
            &[Credential::vault_key(master)],
            salvage_tdenc2::Argon2Params::WRITER_DEFAULT,
            SessionRandomness {
                dek: [23; 32],
                uuid: [17; 16],
                nonce_prefix: [19; 16],
            },
            &[SlotRandomness {
                salt: [11; 16],
                wrapping_nonce: [13; 24],
            }],
        )
        .map_err(|error| error.to_string())?;
        let expected = std::fs::read(vectors.join(golden)).map_err(|error| error.to_string())?;
        let initial_decode = temporary.join(format!("initial-{golden}"));
        decrypt_to_file(&expected, &initial_decode, master)?;
        if std::fs::read(&initial_decode).map_err(|error| error.to_string())? != plaintext {
            return Err(format!("initial reference decryption differs for {golden}"));
        }
        let mut produced = Vec::new();
        session
            .encrypt_reader(&mut Cursor::new(&plaintext), &mut produced)
            .map_err(|error| error.to_string())?;
        if produced != expected {
            let offset = produced
                .iter()
                .zip(expected.iter())
                .position(|(left, right)| left != right);
            let start = offset.unwrap_or(0).saturating_sub(16);
            let end = offset
                .map_or(produced.len(), |value| value + 32)
                .min(produced.len());
            return Err(format!(
                "deterministic bytes differ for {golden} at {offset:?}; produced={} expected={}; produced window={:02x?}; expected window={:02x?}",
                produced.len(),
                expected.len(),
                &produced[start..end],
                &expected[start..end]
            ));
        }

        let continued = EncryptionSession::from_header(
            session.complete_header(),
            plaintext.len() as u64,
            Some(&metadata),
            &[Credential::vault_key(master)],
        )
        .map_err(|error| error.to_string())?;
        let mut continued_bytes = Vec::new();
        continued
            .encrypt_reader(&mut Cursor::new(&plaintext), &mut continued_bytes)
            .map_err(|error| error.to_string())?;
        if continued_bytes != expected {
            return Err(format!("continuation bytes differ for {golden}"));
        }

        let decoded_path = temporary.join(format!("decoded-{golden}"));
        decrypt_to_file(&expected, &decoded_path, master)?;
        if std::fs::read(&decoded_path).map_err(|error| error.to_string())? != plaintext {
            return Err(format!("plaintext differs for {golden}"));
        }

        let header_len =
            u32::from_le_bytes(expected[26..30].try_into().map_err(|_| "header offset")?) as usize;
        let mut variants = vec![
            expected[..20].to_vec(),
            expected[..header_len - 1].to_vec(),
            expected[..expected.len() - 1].to_vec(),
        ];
        for offset in [
            8,
            66,
            150,
            header_len - 1,
            header_len + 9,
            expected.len() - 9,
        ] {
            let mut corrupt = expected.clone();
            corrupt[offset] ^= 1;
            variants.push(corrupt);
        }
        let split = header_len + 1_048_576 + 16;
        let end = expected.len() - 68;
        let mut reordered = expected[..header_len].to_vec();
        reordered.extend_from_slice(&expected[split..end]);
        reordered.extend_from_slice(&expected[header_len..split]);
        reordered.extend_from_slice(&expected[end..]);
        variants.push(reordered);
        let mut trailing = expected.clone();
        trailing.push(0);
        variants.push(trailing);
        for (index, corrupt) in variants.iter().enumerate() {
            let destination = temporary.join(format!("rejected-{golden}-{index}"));
            if decrypt_to_file(corrupt, &destination, master).is_ok() {
                return Err(format!("corrupt variant {index} was accepted for {golden}"));
            }
            if destination.exists() {
                return Err(format!(
                    "corrupt variant {index} published plaintext for {golden}"
                ));
            }
        }
        let wrong_destination = temporary.join(format!("wrong-key-{golden}"));
        if decrypt_to_file(&expected, &wrong_destination, [99; 32]).is_ok()
            || wrong_destination.exists()
        {
            return Err(format!("wrong key published plaintext for {golden}"));
        }
    }

    let vault_bytes =
        std::fs::read(vectors.join("v3.9.8-vault.bin")).map_err(|error| error.to_string())?;
    let recovery_bytes =
        std::fs::read(vectors.join("v3.9.8-recovery.bin")).map_err(|error| error.to_string())?;
    let vault = open_vault(&vault_bytes, b"public v3.9.8 vault fixture passphrase")
        .map_err(|error| error.to_string())?;
    if vault.master_key != master {
        return Err("vault master key differs".to_string());
    }
    let recovered = open_recovery(
        &recovery_bytes,
        b"public v3.9.8 recovery fixture passphrase",
    )
    .map_err(|error| error.to_string())?;
    if recovered.master_key != master {
        return Err("recovery master key differs".to_string());
    }
    let replacement = seal_recovery(&recovered, b"public replacement fixture passphrase")
        .map_err(|error| error.to_string())?;
    let reopened = open_recovery(&replacement, b"public replacement fixture passphrase")
        .map_err(|error| error.to_string())?;
    let replacement_vault = seal_vault(&reopened, b"public replacement vault passphrase")
        .map_err(|error| error.to_string())?;
    let reopened_vault = open_vault(&replacement_vault, b"public replacement vault passphrase")
        .map_err(|error| error.to_string())?;
    if reopened_vault.master_key != master {
        return Err("replacement vault master key differs".to_string());
    }

    println!("{{\"status\":\"ok\",\"envelopes\":2,\"corruption_refused\":true,\"recovery\":true}}");
    Ok(())
}

fn decrypt_to_file(ciphertext: &[u8], destination: &Path, master: [u8; 32]) -> Result<(), String> {
    let mut reader = Cursor::new(ciphertext);
    let mut plaintext = Vec::new();
    decrypt_reader(
        &mut reader,
        &mut plaintext,
        &[Credential::vault_key(master)],
    )
    .map_err(|error| error.to_string())?;
    std::fs::write(destination, plaintext).map_err(|error| error.to_string())
}
