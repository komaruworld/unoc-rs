use assert_cmd::Command;
use predicates::str::contains;

#[test]
fn help_mentions_required_apk_arguments() {
    let mut cmd = Command::cargo_bin("unoc-rs").expect("binary exists");
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(contains("OLD_APK"))
        .stdout(contains("NEW_APK"))
        .stdout(contains("inspect"))
        .stdout(contains("query"))
        .stdout(contains("remap"))
        .stdout(contains("--threads"))
        .stdout(contains("--memory-limit"))
        .stdout(contains("--min-confidence"));
}

#[test]
fn rejects_invalid_threshold_order() {
    let mut cmd = Command::cargo_bin("unoc-rs").expect("binary exists");
    cmd.args([
        "old.apk",
        "new.apk",
        "-o",
        "report",
        "--min-confidence",
        "0.40",
        "--low-confidence",
        "0.60",
    ])
    .assert()
    .failure()
    .stderr(contains(
        "min-confidence must be greater than or equal to low-confidence",
    ));
}

#[cfg(not(unix))]
#[test]
fn rejects_memory_limits_on_unsupported_platforms() {
    Command::cargo_bin("unoc-rs")
        .expect("binary exists")
        .args(["--memory-limit", "12g"])
        .assert()
        .failure()
        .stderr(contains("use --memory-limit 0"));
}
