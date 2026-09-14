mod common;

use assert_cmd::Command;
use tempfile::tempdir;

use common::apk_fixture::write_zip_apk;
use common::dex_fixture::empty_dex_header;

#[test]
fn inspect_writes_summary_and_json() {
    let temp = tempdir().expect("temp dir");
    let apk = temp.path().join("app.apk");
    let report = temp.path().join("inspect");
    write_zip_apk(&apk, &[("classes.dex", &empty_dex_header("035"))]);

    Command::cargo_bin("unoc-rs")
        .expect("binary exists")
        .args([
            "inspect",
            apk.to_str().expect("apk"),
            "-o",
            report.to_str().expect("report"),
        ])
        .assert()
        .success();

    assert!(report.join("inspect-summary.txt").exists());
    assert!(report.join("inspect.json").exists());
}
