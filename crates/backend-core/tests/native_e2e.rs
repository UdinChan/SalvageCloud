use std::process::Command;

#[test]
fn telegram_session_catch_up_uses_batched_encrypted_persistence() {
    let output = Command::new(env!("CARGO_BIN_EXE_salvage-session-e2e-driver"))
        .output()
        .expect("run Telegram session storage child journey");
    assert!(
        output.status.success(),
        "child journey failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("driver JSON output");
    assert!(
        stdout.contains("\"status\":\"ok\""),
        "unexpected driver output: {stdout}"
    );
}
