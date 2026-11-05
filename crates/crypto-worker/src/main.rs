#[cfg(target_arch = "wasm32")]
fn main() {
    salvage_crypto_worker::start_worker();
}

#[cfg(not(target_arch = "wasm32"))]
fn main() {}
