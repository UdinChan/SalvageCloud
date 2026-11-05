use std::fmt::Write as _;

use js_sys::Uint8Array;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Blob, File};

const RESUME_KEY: &str = "salvage-cloud.upload-resume-metadata.v1";
const MAX_RESUME_RECORDS: usize = 50;

/// The only upload data persisted by the browser. File bytes and credentials
/// deliberately have no representation in this record.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResumeMetadata {
    pub transfer_id: Uuid,
    pub name: String,
    pub size: u64,
    #[serde(rename = "lastModified")]
    pub last_modified_ms: i64,
    pub folder_id: Option<String>,
    #[serde(default)]
    pub bot_id: Option<Uuid>,
    #[serde(default)]
    pub bot_auto: bool,
    pub next_offset: u64,
}

impl ResumeMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        transfer_id: Uuid,
        name: String,
        size: u64,
        last_modified_ms: i64,
        folder_id: Option<String>,
        bot_id: Option<Uuid>,
        bot_auto: bool,
        next_offset: u64,
    ) -> Self {
        Self {
            transfer_id,
            name,
            size,
            last_modified_ms,
            folder_id,
            bot_id,
            bot_auto,
            next_offset,
        }
    }

    fn matches(
        &self,
        name: &str,
        size: u64,
        last_modified_ms: i64,
        folder_id: Option<&str>,
        bot_id: Option<Uuid>,
        bot_auto: bool,
    ) -> bool {
        self.name == name
            && self.size == size
            && self.last_modified_ms == last_modified_ms
            && self.folder_id.as_deref() == folder_id
            && self.bot_id == bot_id
            && self.bot_auto == bot_auto
    }
}

fn storage() -> Option<web_sys::Storage> {
    web_sys::window().and_then(|window| window.local_storage().ok().flatten())
}

fn load() -> Vec<ResumeMetadata> {
    storage()
        .and_then(|storage| storage.get_item(RESUME_KEY).ok().flatten())
        .and_then(|value| serde_json::from_str(&value).ok())
        .unwrap_or_default()
}

fn persist(records: &[ResumeMetadata]) {
    if let Some(storage) = storage()
        && let Ok(value) = serde_json::to_string(records)
    {
        let _ = storage.set_item(RESUME_KEY, &value);
    }
}

pub fn find(
    name: &str,
    size: u64,
    last_modified_ms: i64,
    folder_id: Option<&str>,
    bot_id: Option<Uuid>,
    bot_auto: bool,
) -> Option<ResumeMetadata> {
    load()
        .into_iter()
        .rev()
        .find(|record| record.matches(name, size, last_modified_ms, folder_id, bot_id, bot_auto))
}

pub fn save(record: ResumeMetadata) {
    let mut records = load();
    records.retain(|existing| {
        existing.transfer_id != record.transfer_id
            && !existing.matches(
                &record.name,
                record.size,
                record.last_modified_ms,
                record.folder_id.as_deref(),
                record.bot_id,
                record.bot_auto,
            )
    });
    records.push(record);
    if records.len() > MAX_RESUME_RECORDS {
        let excess = records.len() - MAX_RESUME_RECORDS;
        records.drain(0..excess);
    }
    persist(&records);
}

pub fn remove(transfer_id: Uuid) {
    let mut records = load();
    records.retain(|record| record.transfer_id != transfer_id);
    persist(&records);
}

pub async fn read_chunk(file: &File, start: u64, end: u64) -> Result<Uint8Array, String> {
    let blob = file
        .slice_with_f64_and_f64(start as f64, end as f64)
        .map_err(|error| js_error("The browser couldn’t slice this file", error))?;
    read_blob(blob).await
}

pub async fn sha256_prefix(file: &File, prefix_length: u64) -> Result<String, String> {
    let prefix = file
        .slice_with_f64_and_f64(0.0, prefix_length as f64)
        .map_err(|error| js_error("The browser couldn’t read the staged prefix", error))?;
    let bytes = read_blob(prefix).await?;
    let crypto = web_sys::window()
        .ok_or_else(|| "WebCrypto is unavailable in this browser.".to_owned())?
        .crypto()
        .map_err(|error| js_error("WebCrypto is unavailable", error))?;
    let digest = crypto
        .subtle()
        .digest_with_str_and_js_u8_array("SHA-256", &bytes)
        .map_err(|error| js_error("The staged prefix couldn’t be hashed", error))?;
    let digest = JsFuture::from(digest)
        .await
        .map_err(|error| js_error("The staged prefix couldn’t be hashed", error))?;
    let digest = Uint8Array::new(&digest);
    let mut hexadecimal = String::with_capacity((digest.length() * 2) as usize);
    for index in 0..digest.length() {
        let _ = write!(hexadecimal, "{:02x}", digest.get_index(index));
    }
    Ok(hexadecimal)
}

async fn read_blob(blob: Blob) -> Result<Uint8Array, String> {
    let buffer = JsFuture::from(blob.array_buffer())
        .await
        .map_err(|error| js_error("The browser couldn’t read this file", error))?;
    Ok(Uint8Array::new(&buffer))
}

fn js_error(context: &str, error: JsValue) -> String {
    let detail = error
        .as_string()
        .unwrap_or_else(|| "unknown browser error".to_owned());
    format!("{context}: {detail}.")
}
