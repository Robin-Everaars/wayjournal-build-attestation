use std::process::Command;

#[test]
fn version_flag_reports_the_workspace_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_wayjournal"))
        .arg("--version")
        .output()
        .expect("wayjournal binary should start");

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).expect("version output should be UTF-8"),
        format!("wayjournal {}\n", env!("CARGO_PKG_VERSION"))
    );
}
