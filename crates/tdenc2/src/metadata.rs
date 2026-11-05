use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const METADATA_SCHEMA_VERSION: u16 = 1;
pub const MAX_METADATA_PLAINTEXT: usize = 65_536;

/// Names and optional Folder Sync placement stored only in authenticated ciphertext.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedMetadata {
    pub schema_version: u16,
    pub original_name: String,
    pub mime_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync_path: Option<String>,
}

impl ProtectedMetadata {
    pub fn new(original_name: impl Into<String>, mime_type: impl Into<String>) -> Self {
        Self {
            schema_version: METADATA_SCHEMA_VERSION,
            original_name: original_name.into(),
            mime_type: mime_type.into(),
            sync_path: None,
        }
    }

    pub fn with_sync_path(mut self, sync_path: impl Into<String>) -> Self {
        self.sync_path = Some(sync_path.into());
        self
    }

    /// Produces the frozen compact JSON field order. Placement safety remains a consumer policy.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|error| Error::InvalidMetadata(error.to_string()))
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_METADATA_PLAINTEXT {
            return Err(Error::MetadataTooLarge);
        }
        let metadata: Self = serde_json::from_slice(bytes)
            .map_err(|error| Error::InvalidMetadata(error.to_string()))?;
        metadata.validate()?;
        Ok(metadata)
    }

    fn validate(&self) -> Result<()> {
        if self.schema_version != METADATA_SCHEMA_VERSION {
            return Err(Error::InvalidMetadata(format!(
                "unsupported schema_version {}",
                self.schema_version
            )));
        }
        Ok(())
    }
}
