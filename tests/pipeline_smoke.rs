mod common;

use assert_cmd::Command;
use predicates::str::contains;
use tempfile::tempdir;

use common::apk_fixture::write_zip_apk;
use common::dex_fixture::empty_dex_header;

#[test]
fn shared_class_targets_are_excluded_from_verified_and_safe_remap_reports() {
    use common::dex_fixture::{build_dex, ClassSpec, FieldRef, FieldSpec};
    let class = |name: &str| {
        ClassSpec::new(name)
            .with_field(FieldSpec::instance(FieldRef::new(name, "first", "I")))
            .with_field(FieldSpec::instance(FieldRef::new(name, "second", "J")))
    };
    let temp = tempdir().expect("temp dir");
    let old = temp.path().join("old.apk");
    let new = temp.path().join("new.apk");
    let report = temp.path().join("report");
    write_zip_apk(
        &old,
        &[("classes.dex", &build_dex(&[class("La/A;"), class("La/B;")]))],
    );
    write_zip_apk(&new, &[("classes.dex", &build_dex(&[class("La/C;")]))]);
    Command::cargo_bin("unoc-rs")
        .expect("binary")
        .arg(&old)
        .arg(&new)
        .arg("-o")
        .arg(&report)
        .arg("--verified-only")
        .assert()
        .success();
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(report.join("mapping.json")).expect("JSON"))
            .expect("report");
    let classes = json["matches"]["classes"].as_array().expect("classes");
    assert_eq!(classes.len(), 2);
    assert!(classes.iter().all(|item| item["status"] == "Conflict"));
    let verified = std::fs::read_to_string(report.join("verified.txt")).expect("verified");
    assert_eq!(
        verified.lines().count(),
        1,
        "only the TSV header should remain"
    );
    let source = temp.path().join("source.smali");
    std::fs::write(&source, "La/A; La/B;").expect("source");
    for mapping in ["mapping.json", "mapping.txt", "old-to-new.pro"] {
        Command::cargo_bin("unoc-rs")
            .expect("binary")
            .args(["remap", "-m"])
            .arg(report.join(mapping))
            .arg(&source)
            .arg("-o")
            .arg(temp.path().join("remapped.smali"))
            .assert()
            .failure()
            .stderr(contains("no usable mappings"));
    }
}

#[test]
fn html_report_keeps_untrusted_markup_inside_json_data() {
    use common::dex_fixture::{build_dex, ClassSpec};
    let descriptor = "Lreview/</ScRiPt><script id=untrusted>alert(1)</script><img src=x onerror=alert(2)>&Класс;";
    let temp = tempdir().expect("temp dir");
    let apk = temp.path().join("input.apk");
    let report = temp.path().join("report");
    write_zip_apk(
        &apk,
        &[("classes.dex", &build_dex(&[ClassSpec::new(descriptor)]))],
    );
    Command::cargo_bin("unoc-rs")
        .expect("binary")
        .arg(&apk)
        .arg(&apk)
        .arg("-o")
        .arg(&report)
        .assert()
        .success();
    let html = std::fs::read_to_string(report.join("report.html")).expect("HTML");
    let (_, data_and_suffix) = html
        .split_once("<script id=\"report-data\" type=\"application/json\">")
        .expect("data start");
    let (data, _) = data_and_suffix.split_once("</script>").expect("data end");
    assert!(!data.contains(['<', '>', '&']));
    let json: serde_json::Value = serde_json::from_str(data).expect("complete embedded JSON");
    assert_eq!(json["old_app"]["classes"][0]["descriptor"], descriptor);
    assert_eq!(json["new_app"]["classes"][0]["descriptor"], descriptor);
    assert_eq!(html.to_lowercase().matches("</script>").count(), 2);
}

#[test]
fn writes_reports_for_two_tiny_apks() {
    let temp = tempdir().expect("temp dir");
    let old_apk = temp.path().join("old.apk");
    let new_apk = temp.path().join("new.apk");
    let report = temp.path().join("report");

    write_zip_apk(&old_apk, &[("classes.dex", &empty_dex_header("035"))]);
    write_zip_apk(&new_apk, &[("classes.dex", &empty_dex_header("035"))]);

    let mut cmd = Command::cargo_bin("unoc-rs").expect("binary exists");
    cmd.args([
        old_apk.to_str().expect("old path"),
        new_apk.to_str().expect("new path"),
        "-o",
        report.to_str().expect("report path"),
        "--threads",
        "1",
    ])
    .assert()
    .success();

    assert!(report.join("summary.txt").exists());
    assert!(report.join("mapping.txt").exists());
    assert!(report.join("mapping.json").exists());
    assert!(report.join("report.html").exists());
}

#[test]
fn progress_prints_pipeline_stages() {
    let temp = tempdir().expect("temp dir");
    let old_apk = temp.path().join("old.apk");
    let new_apk = temp.path().join("new.apk");
    let report = temp.path().join("report");
    write_zip_apk(&old_apk, &[("classes.dex", &empty_dex_header("035"))]);
    write_zip_apk(&new_apk, &[("classes.dex", &empty_dex_header("035"))]);

    Command::cargo_bin("unoc-rs")
        .expect("binary exists")
        .args([
            old_apk.to_str().expect("old path"),
            new_apk.to_str().expect("new path"),
            "-o",
            report.to_str().expect("report path"),
            "--progress",
        ])
        .assert()
        .success()
        .stderr(predicates::str::contains("stage: resolve input"))
        .stderr(predicates::str::contains("stage: report"));
}

#[test]
fn missing_input_error_is_actionable() {
    let temp = tempdir().expect("temp dir");
    let mut cmd = Command::cargo_bin("unoc-rs").expect("binary exists");
    let old = temp.path().join("missing-old.apk");
    let new = temp.path().join("missing-new.apk");
    let report = temp.path().join("report");
    cmd.args([
        old.to_str().expect("path"),
        new.to_str().expect("path"),
        "-o",
        report.to_str().expect("path"),
    ])
    .assert()
    .failure()
    .stderr(contains("input APK path does not exist"));
}

#[test]
fn output_is_deterministic_across_thread_counts() {
    let temp = tempdir().expect("temp dir");
    let old_apk = temp.path().join("old.apk");
    let new_apk = temp.path().join("new.apk");
    let report_one = temp.path().join("report-one");
    let report_four = temp.path().join("report-four");

    write_zip_apk(&old_apk, &[("classes.dex", &empty_dex_header("035"))]);
    write_zip_apk(&new_apk, &[("classes.dex", &empty_dex_header("035"))]);

    Command::cargo_bin("unoc-rs")
        .expect("binary exists")
        .args([
            old_apk.to_str().expect("old path"),
            new_apk.to_str().expect("new path"),
            "-o",
            report_one.to_str().expect("report path"),
            "--threads",
            "1",
        ])
        .assert()
        .success();

    Command::cargo_bin("unoc-rs")
        .expect("binary exists")
        .args([
            old_apk.to_str().expect("old path"),
            new_apk.to_str().expect("new path"),
            "-o",
            report_four.to_str().expect("report path"),
            "--threads",
            "4",
        ])
        .assert()
        .success();

    let one = std::fs::read_to_string(report_one.join("mapping.json")).expect("json one");
    let four = std::fs::read_to_string(report_four.join("mapping.json")).expect("json four");
    assert_eq!(one, four);
}
