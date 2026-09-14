mod common;

use assert_cmd::Command;
use predicates::str::contains;
use tempfile::tempdir;

use common::apk_fixture::write_zip_apk;
use common::dex_fixture::empty_dex_header;

#[test]
fn remap_applies_chains_and_swaps_once_without_changing_other_names() {
    for (mapping_text, input_text, expected) in [
        (
            "La/A; -> La/B;\nLa/B; -> La/C;\n",
            "La/A; La/B; La/Ab; La/A$Inner; a/A a/Ab a.A a.Ab a.A.run() a.A\u{301}\n(ILa/A;[La/B;ZLa/A;)V",
            "La/B; La/C; La/Ab; La/A$Inner; a/B a/Ab a.B a.Ab a.B.run() a.A\u{301}\n(ILa/B;[La/C;ZLa/B;)V",
        ),
        (
            "La/A; -> La/B;\nLa/B; -> La/A;\n",
            "La/A; La/B; a.A a.B",
            "La/B; La/A; a.B a.A",
        ),
        ("La/A; -> La/AA;\n", "La/A; a/A a.A", "La/AA; a/AA a.AA"),
        (
            "Lпример/Класс; -> Lновый/Класс;\n",
            "Lпример/Класс; пример.Класс.run()",
            "Lновый/Класс; новый.Класс.run()",
        ),
    ] {
        let temp = tempdir().expect("temp dir");
        let mapping = temp.path().join("mapping.txt");
        let input = temp.path().join("input.txt");
        let output = temp.path().join("output.txt");
        std::fs::write(&mapping, mapping_text).expect("mapping");
        std::fs::write(&input, input_text).expect("input");
        Command::cargo_bin("unoc-rs")
            .expect("binary")
            .args(["remap", "-m"])
            .arg(&mapping)
            .arg(&input)
            .arg("-o")
            .arg(&output)
            .assert()
            .success();
        assert_eq!(std::fs::read_to_string(&output).expect("output"), expected);
        assert_eq!(std::fs::read_to_string(&input).expect("input"), input_text);
    }
}

#[test]
fn remap_rejects_overlapping_paths_before_creating_output() {
    let temp = tempdir().expect("temp dir");
    let mapping = temp.path().join("mapping.txt");
    let input = temp.path().join("input");
    std::fs::create_dir(&input).expect("input dir");
    std::fs::write(&mapping, "La/A; -> La/B;\n").expect("mapping");
    let source = input.join("A.smali");
    std::fs::write(&source, "La/A;").expect("source");
    for output in [
        input.clone(),
        input.join("nested"),
        input.join("missing/../nested"),
        temp.path().to_path_buf(),
    ] {
        Command::cargo_bin("unoc-rs")
            .expect("binary")
            .args(["remap", "-m"])
            .arg(&mapping)
            .arg(&input)
            .arg("-o")
            .arg(&output)
            .assert()
            .failure()
            .stderr(contains("must not overlap"));
    }
    Command::cargo_bin("unoc-rs")
        .expect("binary")
        .args(["remap", "-m"])
        .arg(&mapping)
        .arg(&source)
        .arg("-o")
        .arg(&source)
        .assert()
        .failure()
        .stderr(contains("must not overlap"));
    assert_eq!(std::fs::read_to_string(&source).expect("source"), "La/A;");
    assert_eq!(std::fs::read_dir(&input).expect("input entries").count(), 1);
}

#[cfg(unix)]
#[test]
fn remap_rejects_symlink_aliases_and_directory_loops() {
    let temp = tempdir().expect("temp dir");
    let mapping = temp.path().join("mapping.txt");
    let input = temp.path().join("input");
    let alias = temp.path().join("alias");
    std::fs::create_dir(&input).expect("input dir");
    std::fs::write(&mapping, "La/A; -> La/B;\n").expect("mapping");
    std::os::unix::fs::symlink(&input, &alias).expect("alias");
    Command::cargo_bin("unoc-rs")
        .expect("binary")
        .args(["remap", "-m"])
        .arg(&mapping)
        .arg(&input)
        .arg("-o")
        .arg(alias.join("nested"))
        .assert()
        .failure()
        .stderr(contains("must not overlap"));
    assert!(!input.join("nested").exists());
    std::os::unix::fs::symlink(&input, input.join("loop")).expect("loop");
    Command::cargo_bin("unoc-rs")
        .expect("binary")
        .args(["remap", "-m"])
        .arg(&mapping)
        .arg(&input)
        .arg("-o")
        .arg(temp.path().join("output"))
        .assert()
        .failure()
        .stderr(contains("does not follow symbolic links"));
}

#[test]
fn query_prints_class_match_from_mapping_json() {
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
            "--no-html",
        ])
        .assert()
        .success();

    let mapping = report.join("mapping.json");
    assert!(mapping.exists());

    Command::cargo_bin("unoc-rs")
        .expect("binary exists")
        .args([
            "query",
            "-m",
            mapping.to_str().expect("mapping path"),
            "LX/0hp4;",
        ])
        .assert()
        .failure()
        .stderr(contains("class not found in mapping"));
}

#[test]
fn remap_rewrites_smali_descriptors_from_mapping_txt() {
    let temp = tempdir().expect("temp dir");
    let mapping = temp.path().join("mapping.txt");
    let input = temp.path().join("input");
    let output = temp.path().join("output");
    std::fs::create_dir_all(input.join("a")).expect("input dir");
    std::fs::write(
        &mapping,
        "[0.96] La/Old; (base.apk!classes.dex#1) -> Lb/New; (base.apk!classes.dex#2)\n",
    )
    .expect("mapping");
    std::fs::write(
        input.join("a/Old.smali"),
        ".class public La/Old;\n.super Ljava/lang/Object;\n\ninvoke-static {}, La/Old;->run()V\n",
    )
    .expect("smali");

    Command::cargo_bin("unoc-rs")
        .expect("binary exists")
        .args([
            "remap",
            "-m",
            mapping.to_str().expect("mapping path"),
            input.to_str().expect("input path"),
            "-o",
            output.to_str().expect("output path"),
        ])
        .assert()
        .success();

    let remapped = std::fs::read_to_string(output.join("a/Old.smali")).expect("remapped smali");
    assert!(remapped.contains("Lb/New;"));
    assert!(!remapped.contains("La/Old;"));
}
