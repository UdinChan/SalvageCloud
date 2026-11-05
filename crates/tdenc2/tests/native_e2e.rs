use std::{path::Path, process::Command};

#[test]
fn tdenc2_public_vectors_and_corruption_journeys_pass_in_child_process() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/tdenc2");
    let output = Command::new(env!("CARGO_BIN_EXE_tdenc2-e2e-driver"))
        .arg(&fixtures)
        .output()
        .expect("run TDENC2 child-process journey");
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
