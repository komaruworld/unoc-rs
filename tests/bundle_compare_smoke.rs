mod common;

use assert_cmd::Command;
use tempfile::tempdir;

use common::apk_fixture::write_zip_apk;
use common::dex_fixture::empty_dex_header;

#[test]
fn compare_accepts_apks_bundle_inputs() {
    let temp = tempdir().expect("temp dir");
    let old_bundle = temp.path().join("old.apks");
    let new_bundle = temp.path().join("new.apks");
    let report = temp.path().join("report");
    let old_base = zip_apk_bytes();
    let new_base = zip_apk_bytes();

    write_zip_apk(&old_bundle, &[("base.apk", &old_base)]);
    write_zip_apk(&new_bundle, &[("base.apk", &new_base)]);

    Command::cargo_bin("unoc-rs")
        .expect("binary exists")
        .args([
            old_bundle.to_str().expect("old bundle"),
            new_bundle.to_str().expect("new bundle"),
            "-o",
            report.to_str().expect("report"),
        ])
        .assert()
        .success();

    assert!(report.join("mapping.json").exists());
    let summary = std::fs::read_to_string(report.join("summary.txt")).expect("summary");
    assert!(summary.contains("old_apk_parts: 1"));
    assert!(summary.contains("new_apk_parts: 1"));
}

#[test]
fn compare_skips_bundle_parts_without_dex() {
    let temp = tempdir().expect("temp dir");
    let old_bundle = temp.path().join("old.xapk");
    let new_bundle = temp.path().join("new.xapk");
    let report = temp.path().join("report");
    let old_base = zip_apk_bytes();
    let new_base = zip_apk_bytes();
    let no_dex = zip_apk_without_dex_bytes();

    write_zip_apk(
        &old_bundle,
        &[("base.apk", &old_base), ("split_config.en.apk", &no_dex)],
    );
    write_zip_apk(
        &new_bundle,
        &[("base.apk", &new_base), ("split_config.en.apk", &no_dex)],
    );

    Command::cargo_bin("unoc-rs")
        .expect("binary exists")
        .args([
            old_bundle.to_str().expect("old bundle"),
            new_bundle.to_str().expect("new bundle"),
            "-o",
            report.to_str().expect("report"),
        ])
        .assert()
        .success();

    assert!(report.join("mapping.json").exists());
    let summary = std::fs::read_to_string(report.join("summary.txt")).expect("summary");
    assert!(summary.contains("old_apk_parts: 2"));
    assert!(summary.contains("new_apk_parts: 2"));
}

fn zip_apk_bytes() -> Vec<u8> {
    let temp = tempdir().expect("nested temp");
    let apk = temp.path().join("base.apk");
    write_zip_apk(&apk, &[("classes.dex", &empty_dex_header("035"))]);
    std::fs::read(apk).expect("apk bytes")
}

fn zip_apk_without_dex_bytes() -> Vec<u8> {
    let temp = tempdir().expect("nested temp");
    let apk = temp.path().join("split.apk");
    write_zip_apk(&apk, &[("resources.arsc", b"resources")]);
    std::fs::read(apk).expect("apk bytes")
}
