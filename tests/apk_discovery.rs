mod common;

use pretty_assertions::assert_eq;
use tempfile::tempdir;
use unoc_rs::apk::{read_apk, read_apk_part};

use common::apk_fixture::write_zip_apk;

#[test]
fn finds_and_orders_multi_dex_entries() {
    let temp = tempdir().expect("temp dir");
    let apk = temp.path().join("app.apk");
    write_zip_apk(
        &apk,
        &[
            ("classes3.dex", b"dex\n035\0third"),
            ("assets/readme.txt", b"ignored"),
            ("classes.dex", b"dex\n035\0first"),
            ("classes2.dex", b"dex\n035\0second"),
        ],
    );

    let input = read_apk(&apk).expect("read apk");
    let names: Vec<_> = input
        .dex_files
        .iter()
        .map(|dex| dex.name.as_str())
        .collect();
    assert_eq!(names, vec!["classes.dex", "classes2.dex", "classes3.dex"]);
    assert_eq!(input.dex_files[0].dex_index, 0);
    assert_eq!(input.dex_files[1].dex_index, 1);
    assert_eq!(input.dex_files[2].dex_index, 2);
}

#[test]
fn returns_error_when_apk_has_no_dex_entries() {
    let temp = tempdir().expect("temp dir");
    let apk = temp.path().join("empty.apk");
    write_zip_apk(&apk, &[("AndroidManifest.xml", b"manifest")]);

    let err = read_apk(&apk).expect_err("no dex error");
    assert!(err.to_string().contains("no DEX files found"));
}

#[test]
fn dex_blob_records_apk_part_name() {
    let temp = tempdir().expect("temp dir");
    let apk = temp.path().join("base.apk");
    write_zip_apk(&apk, &[("classes.dex", b"dex\n035\0first")]);

    let input = read_apk_part(&apk, "base.apk").expect("read apk part");

    assert_eq!(input.dex_files[0].apk_part, "base.apk");
    assert_eq!(input.dex_files[0].name, "classes.dex");
}
