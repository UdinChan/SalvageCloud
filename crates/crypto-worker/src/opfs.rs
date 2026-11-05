//! Synchronous OPFS files for use only inside a Dedicated Worker.

use std::io::{Read, Seek, SeekFrom, Write};

use js_sys::Uint8Array;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    FileSystemDirectoryHandle, FileSystemFileHandle, FileSystemGetFileOptions,
    FileSystemReadWriteOptions, FileSystemSyncAccessHandle, WorkerGlobalScope,
};

use crate::protocol::{WorkerError, WorkerResult};

const MAX_SAFE_POSITION: u64 = 9_007_199_254_740_991;

fn io_error(context: &str) -> std::io::Error {
    std::io::Error::other(context.to_owned())
}

fn js_error(context: &str) -> WorkerError {
    WorkerError::new(context.to_owned())
}

fn position(value: u64) -> std::io::Result<f64> {
    if value > MAX_SAFE_POSITION {
        return Err(io_error(
            "OPFS position exceeds the exact JavaScript integer range",
        ));
    }
    Ok(value as f64)
}

/// A cursor-based `Read + Seek + Write` adapter using positional OPFS operations.
/// Construct this only after `create_sync_access_handle()` in a Dedicated Worker.
pub struct OpfsFile {
    handle: FileSystemSyncAccessHandle,
    cursor: u64,
}

impl OpfsFile {
    pub fn new(handle: FileSystemSyncAccessHandle) -> Self {
        Self { handle, cursor: 0 }
    }

    pub fn len(&self) -> WorkerResult<u64> {
        let size = self
            .handle
            .get_size()
            .map_err(|_| js_error("could not read OPFS file size"))?;
        if !size.is_finite() || size < 0.0 || size > MAX_SAFE_POSITION as f64 {
            return Err(js_error("OPFS file size is outside the supported range"));
        }
        Ok(size as u64)
    }

    pub fn is_empty(&self) -> WorkerResult<bool> {
        Ok(self.len()? == 0)
    }

    /// Writes a stream chunk without copying it into a Rust whole-file buffer.
    pub(crate) fn write_js_array(&mut self, value: &Uint8Array) -> std::io::Result<()> {
        let mut offset = 0_u32;
        while offset < value.length() {
            let end = offset.saturating_add(1_048_576).min(value.length());
            let part = value.subarray(offset, end);
            let options = FileSystemReadWriteOptions::new();
            options.set_at(position(self.cursor)?);
            let written = self
                .handle
                .write_with_js_u8_array_and_options(&part, &options)
                .map_err(|_| io_error("OPFS positional write failed"))?;
            if !written.is_finite() || written <= 0.0 || written > part.length() as f64 {
                return Err(io_error("OPFS positional write returned an invalid length"));
            }
            let written = written as u32;
            self.cursor = self
                .cursor
                .checked_add(u64::from(written))
                .ok_or_else(|| io_error("OPFS cursor overflow"))?;
            offset = offset
                .checked_add(written)
                .ok_or_else(|| io_error("OPFS chunk offset overflow"))?;
        }
        Ok(())
    }
}

impl Read for OpfsFile {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let options = FileSystemReadWriteOptions::new();
        options.set_at(position(self.cursor)?);
        let count = self
            .handle
            .read_with_u8_array_and_options(buffer, &options)
            .map_err(|_| io_error("OPFS positional read failed"))?;
        if !count.is_finite() || count < 0.0 || count > buffer.len() as f64 {
            return Err(io_error("OPFS positional read returned an invalid length"));
        }
        let count = count as usize;
        self.cursor = self
            .cursor
            .checked_add(count as u64)
            .ok_or_else(|| io_error("OPFS cursor overflow"))?;
        Ok(count)
    }
}

impl Seek for OpfsFile {
    fn seek(&mut self, position_from: SeekFrom) -> std::io::Result<u64> {
        let next = match position_from {
            SeekFrom::Start(offset) => i128::from(offset),
            SeekFrom::Current(offset) => i128::from(self.cursor) + i128::from(offset),
            SeekFrom::End(offset) => {
                let length = self
                    .handle
                    .get_size()
                    .map_err(|_| io_error("could not read OPFS file size"))?;
                if !length.is_finite() || length < 0.0 || length > MAX_SAFE_POSITION as f64 {
                    return Err(io_error("OPFS file size is outside the supported range"));
                }
                i128::from(length as u64) + i128::from(offset)
            }
        };
        if next < 0 || next > i128::from(MAX_SAFE_POSITION) {
            return Err(io_error(
                "invalid seek to a negative or unsupported OPFS position",
            ));
        }
        self.cursor = next as u64;
        Ok(self.cursor)
    }
}

impl Write for OpfsFile {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let options = FileSystemReadWriteOptions::new();
        options.set_at(position(self.cursor)?);
        let count = self
            .handle
            .write_with_u8_array_and_options(buffer, &options)
            .map_err(|_| io_error("OPFS positional write failed"))?;
        if !count.is_finite() || count < 0.0 || count > buffer.len() as f64 {
            return Err(io_error("OPFS positional write returned an invalid length"));
        }
        let count = count as usize;
        self.cursor = self
            .cursor
            .checked_add(count as u64)
            .ok_or_else(|| io_error("OPFS cursor overflow"))?;
        Ok(count)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.handle
            .flush()
            .map_err(|_| io_error("OPFS flush failed"))
    }
}

impl Drop for OpfsFile {
    fn drop(&mut self) {
        self.handle.close();
    }
}

pub(crate) async fn worker_opfs_root() -> WorkerResult<FileSystemDirectoryHandle> {
    let worker = js_sys::global()
        .dyn_into::<WorkerGlobalScope>()
        .map_err(|_| js_error("OPFS sync access handles require a Dedicated Worker"))?;
    let directory = JsFuture::from(worker.navigator().storage().get_directory())
        .await
        .map_err(|_| js_error("OPFS is unavailable in this browser"))?;
    directory
        .dyn_into::<FileSystemDirectoryHandle>()
        .map_err(|_| js_error("browser returned an invalid OPFS root"))
}

pub(crate) async fn create_opfs_file(
    root: &FileSystemDirectoryHandle,
    name: &str,
) -> WorkerResult<(FileSystemFileHandle, OpfsFile)> {
    let options = FileSystemGetFileOptions::new();
    options.set_create(true);
    let file = JsFuture::from(root.get_file_handle_with_options(name, &options))
        .await
        .map_err(|_| js_error("could not create an OPFS file"))?
        .dyn_into::<FileSystemFileHandle>()
        .map_err(|_| js_error("browser returned an invalid OPFS file handle"))?;
    let handle = JsFuture::from(file.create_sync_access_handle())
        .await
        .map_err(|_| js_error("could not create an OPFS sync access handle"))?
        .dyn_into::<FileSystemSyncAccessHandle>()
        .map_err(|_| js_error("browser returned an invalid OPFS sync access handle"))?;
    Ok((file, OpfsFile::new(handle)))
}

pub(crate) async fn remove_opfs_file(
    root: &FileSystemDirectoryHandle,
    name: &str,
) -> WorkerResult<()> {
    JsFuture::from(root.remove_entry(name))
        .await
        .map_err(|_| js_error("could not remove OPFS entry"))?;
    Ok(())
}
