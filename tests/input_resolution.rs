mod common;

use std::fs;

use pretty_assertions::assert_eq;
use tempfile::tempdir;
use unoc_rs::input::{resolve_app_input, InputKind};

use common::apk_fixture::write_zip_apk;

#[test]
fn resolves_single_apk_as_one_part() {
    let temp = tempdir().expect("temp dir");
    let apk = temp.path().join("app.apk");
    write_zip_apk(&apk, &[("classes.dex", b"dex\n035\0")]);

    let resolved = resolve_app_input(&apk).expect("resolve");

    assert_eq!(resolved.kind, InputKind::ApkFile);
    assert_eq!(resolved.parts.len(), 1);
    assert_eq!(resolved.parts[0].part_name, "app.apk");
}

#[test]
fn resolves_split_directory_sorted_by_name_with_base_first() {
    let temp = tempdir().expect("temp dir");
    let dir = temp.path().join("splits");
    fs::create_dir(&dir).expect("split dir");
    write_zip_apk(
        &dir.join("split_config.arm64_v8a.apk"),
        &[("classes.dex", b"dex\n035\0")],
    );
    write_zip_apk(&dir.join("base.apk"), &[("classes.dex", b"dex\n035\0")]);

    let resolved = resolve_app_input(&dir).expect("resolve");
    let names: Vec<_> = resolved
        .parts
        .iter()
        .map(|part| part.part_name.as_str())
        .collect();

    assert_eq!(resolved.kind, InputKind::SplitDirectory);
    assert_eq!(names, vec!["base.apk", "split_config.arm64_v8a.apk"]);
}

#[test]
fn resolves_bundle_archive_inside_split_directory() {
    let temp = tempdir().expect("temp dir");
    let dir = temp.path().join("download");
    fs::create_dir(&dir).expect("download dir");
    write_zip_apk(
        &dir.join("app.xapk"),
        &[
            ("splits/split_config.en.apk", b"PK fake apk bytes"),
            ("base.apk", b"PK fake base bytes"),
        ],
    );

    let resolved = resolve_app_input(&dir).expect("resolve");
    let names: Vec<_> = resolved
        .parts
        .iter()
        .map(|part| part.part_name.as_str())
        .collect();

    assert_eq!(resolved.kind, InputKind::SplitDirectory);
    assert_eq!(
        names,
        vec!["app.xapk!base.apk", "app.xapk!split_config.en.apk"]
    );
}

#[test]
fn resolves_apks_archive_entries() {
    let temp = tempdir().expect("temp dir");
    let bundle = temp.path().join("app.apks");
    write_zip_apk(
        &bundle,
        &[
            ("splits/split_config.en.apk", b"PK fake apk bytes"),
            ("base.apk", b"PK fake base bytes"),
            ("toc.pb", b"ignored"),
        ],
    );

    let resolved = resolve_app_input(&bundle).expect("resolve");
    let names: Vec<_> = resolved
        .parts
        .iter()
        .map(|part| part.part_name.as_str())
        .collect();

    assert_eq!(resolved.kind, InputKind::BundleArchive);
    assert_eq!(names, vec!["base.apk", "split_config.en.apk"]);
}
