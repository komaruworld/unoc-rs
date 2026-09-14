mod common;

use std::fs;
use std::path::Path;

use assert_cmd::Command;
use predicates::str::contains;
use tempfile::tempdir;

use common::apk_fixture::write_zip_apk;
use common::dex_fixture::{
    build_dex, ClassSpec, FieldRef, FieldSpec, Instruction, MethodRef, MethodSpec,
};

const BASE: &str = "Ltest/Base;";
const CONTRACT: &str = "Ltest/Contract;";
const SECONDARY: &str = "Ltest/Secondary;";
const SOURCE: &str = "Lbridge/Source;";
const TARGET: &str = "Ltest/Target;";

#[test]
fn incomplete_source_parsing_cannot_pass_even_with_allow_missing() {
    for selected_from_bundle in [false, true] {
        for invalid_reference in [false, true] {
            let temp = tempdir().expect("temp dir");
            let target = temp.path().join("target.apk");
            let source = temp.path().join("bridge.dex");
            let report = temp.path().join("report");
            let mut bytes = source_dex(vec![Instruction::InvokeStatic(method_ref(
                "Lmissing/Owner;",
                "run",
                &[],
                "V",
            ))]);
            let parsed = unoc_rs::dex::parse_dex(&bytes).expect("valid source fixture");
            let (&code_off, code) = parsed.raw.code_items.first_key_value().expect("code");
            let code_start = code_off as usize + 16;
            if invalid_reference {
                bytes[code_start + 2..code_start + 4].copy_from_slice(&u16::MAX.to_le_bytes());
            } else {
                // Replace return-void with a truncated five-unit instruction.
                let last = code_start + (code.insns_size as usize - 1) * 2;
                bytes[last..last + 2].copy_from_slice(&0x18u16.to_le_bytes());
            }
            let target_dex = build_dex(&[ClassSpec::new(TARGET)]);
            if selected_from_bundle {
                write_zip_apk(
                    &target,
                    &[("classes.dex", &target_dex), ("classes2.dex", &bytes)],
                );
            } else {
                write_zip_apk(&target, &[("classes.dex", &target_dex)]);
                fs::write(&source, &bytes).expect("source");
            }
            let mut command = audit_command(&target, &report);
            command.args(["--allow-missing", "1000"]);
            if selected_from_bundle {
                command.args(["--source-dex", "classes2.dex"]);
            } else {
                command.arg("--references").arg(&source);
            }
            command
                .assert()
                .failure()
                .stderr(contains("incomplete DEX parsing"));
            assert!(!report.join("summary.txt").exists());
        }
    }
}

#[test]
fn reports_each_missing_reason_and_honors_allow_missing() {
    let temp = tempdir().expect("temp dir");
    let target = temp.path().join("target.apk");
    let source = temp.path().join("bridge.dex");
    let report = temp.path().join("report");
    let allowed_report = temp.path().join("allowed-report");
    let mapping = temp.path().join("mapping.txt");

    write_zip_apk(
        &target,
        &[("classes.dex", &build_dex(&compatibility_classes()))],
    );
    fs::write(
        &source,
        source_dex(vec![
            Instruction::InvokeVirtual(method_ref("Lmissing/Owner;", "run", &[], "V")),
            Instruction::InvokeVirtual(method_ref(TARGET, "missing", &[], "V")),
            Instruction::ReadInstanceField(field_ref(TARGET, "missing", "I")),
            Instruction::InvokeVirtual(method_ref(TARGET, "changed", &["Ljava/lang/String;"], "V")),
            Instruction::ReadInstanceField(field_ref(TARGET, "changed", "Ljava/lang/String;")),
        ]),
    )
    .expect("source dex");
    fs::write(&mapping, "Lmissing/Owner; -> Ltest/Target;\n").expect("mapping");

    let mut command = audit_command(&target, &report);
    command
        .arg("--references")
        .arg(&source)
        .arg("--mapping")
        .arg(&mapping);
    command
        .assert()
        .failure()
        .stderr(contains("reference audit found 5 unresolved site(s)"));

    let summary = read_report(&report, "summary.txt");
    assert!(summary.contains("unresolved_references: 5"));
    assert!(summary.contains("status: FAIL"));
    let unresolved = read_report(&report, "unresolved-refs.tsv");
    for reason in [
        "missing_owner",
        "missing_method",
        "missing_field",
        "changed_prototype",
        "changed_descriptor",
    ] {
        assert!(unresolved.contains(reason), "missing reason {reason}");
    }
    assert!(unresolved.contains("mapped_owner=Ltest/Target;"));
    assert!(unresolved.contains("\t0x"));

    let mut allowed = audit_command(&target, &allowed_report);
    allowed
        .arg("--references")
        .arg(&source)
        .args(["--allow-missing", "5"]);
    allowed.assert().success();
    assert!(read_report(&allowed_report, "summary.txt").contains("status: PASS"));
}

#[test]
fn resolves_inherited_virtual_methods_fields_and_interfaces() {
    let temp = tempdir().expect("temp dir");
    let target = temp.path().join("target.apk");
    let source = temp.path().join("bridge.dex");
    let report = temp.path().join("report");
    write_zip_apk(
        &target,
        &[("classes.dex", &build_dex(&compatibility_classes()))],
    );
    fs::write(
        &source,
        source_dex(vec![
            Instruction::InvokeVirtual(method_ref(TARGET, "inherited", &[], "V")),
            Instruction::ReadInstanceField(field_ref(TARGET, "value", "I")),
            Instruction::InvokeVirtual(method_ref(TARGET, "work", &[], "V")),
            Instruction::InvokeInterface(method_ref(CONTRACT, "work", &[], "V")),
        ]),
    )
    .expect("source dex");

    let mut command = audit_command(&target, &report);
    command.arg("--references").arg(&source);
    command.assert().success();

    let summary = read_report(&report, "summary.txt");
    assert!(summary.contains("references_resolved: 4"));
    assert!(summary.contains("unresolved_references: 0"));
    assert!(summary.contains("status: PASS"));
}

#[test]
fn requires_static_members_and_constructors_on_the_declared_owner() {
    let temp = tempdir().expect("temp dir");
    let target = temp.path().join("target.apk");
    let source = temp.path().join("bridge.dex");
    let report = temp.path().join("report");
    write_zip_apk(
        &target,
        &[("classes.dex", &build_dex(&compatibility_classes()))],
    );
    fs::write(
        &source,
        source_dex(vec![
            Instruction::InvokeStatic(method_ref(TARGET, "inheritedStatic", &[], "V")),
            Instruction::InvokeDirect(method_ref(TARGET, "<init>", &[], "V")),
            Instruction::ReadStaticField(field_ref(TARGET, "staticFlag", "I")),
            Instruction::InvokeStatic(method_ref(TARGET, "ok", &[], "V")),
            Instruction::ReadStaticField(field_ref(TARGET, "ownValue", "I")),
        ]),
    )
    .expect("source dex");

    let mut command = audit_command(&target, &report);
    command.arg("--references").arg(&source);
    command.assert().failure();

    let summary = read_report(&report, "summary.txt");
    assert!(summary.contains("missing_method: 2"));
    assert!(summary.contains("missing_field: 1"));
    assert!(summary.contains("member_kind_mismatch: 2"));
}

#[test]
fn selected_source_dex_resolves_definition_from_secondary_split() {
    let temp = tempdir().expect("temp dir");
    let base_apk = temp.path().join("base.apk");
    let feature_apk = temp.path().join("feature.apk");
    let bundle = temp.path().join("patched.xapk");
    let report = temp.path().join("report");
    let source = source_dex(vec![Instruction::InvokeVirtual(method_ref(
        SECONDARY,
        "split",
        &[],
        "V",
    ))]);
    write_zip_apk(
        &base_apk,
        &[
            (
                "classes.dex",
                &build_dex(&[ClassSpec::new("Ltest/Placeholder;")]),
            ),
            ("classes2.dex", &source),
        ],
    );
    write_zip_apk(
        &feature_apk,
        &[(
            "classes.dex",
            &build_dex(&[
                ClassSpec::new(SECONDARY).with_method(MethodSpec::virtual_method(method_ref(
                    SECONDARY,
                    "split",
                    &[],
                    "V",
                ))),
            ]),
        )],
    );
    let base_bytes = fs::read(&base_apk).expect("base apk");
    let feature_bytes = fs::read(&feature_apk).expect("feature apk");
    write_zip_apk(
        &bundle,
        &[
            ("base.apk", &base_bytes),
            ("split_feature.apk", &feature_bytes),
        ],
    );

    let mut command = audit_command(&bundle, &report);
    command
        .args(["--source-dex", "base.apk!classes2.dex"])
        .assert()
        .success();

    let summary = read_report(&report, "summary.txt");
    assert!(summary.contains("target_parts: 2"));
    assert!(summary.contains("source_dex_files: 1"));
    assert!(summary.contains("resolved_in_another_split: 1"));
    assert!(summary.contains("status: PASS"));
}

#[test]
fn reports_changed_prototype_for_invoke_interface_range() {
    let temp = tempdir().expect("temp dir");
    let target = temp.path().join("target.apk");
    let source = temp.path().join("bridge.dex");
    let report = temp.path().join("report");
    let api = "Ltest/RangeApi;";
    let old_continuation = "Ltest/OldContinuation;";
    let new_continuation = "Ltest/NewContinuation;";
    let target_classes = [
        ClassSpec::interface(api).with_method(MethodSpec::abstract_virtual(method_ref(
            api,
            "submit",
            &[new_continuation],
            "V",
        ))),
        ClassSpec::new(old_continuation),
        ClassSpec::new(new_continuation),
    ];
    write_zip_apk(&target, &[("classes.dex", &build_dex(&target_classes))]);
    fs::write(
        &source,
        source_dex(vec![Instruction::InvokeInterfaceRange(method_ref(
            api,
            "submit",
            &[old_continuation],
            "V",
        ))]),
    )
    .expect("source dex");

    let mut command = audit_command(&target, &report);
    command.arg("--references").arg(&source);
    command.assert().failure();

    let unresolved = read_report(&report, "unresolved-refs.tsv");
    assert!(unresolved.contains("method\tLtest/RangeApi;->submit(Ltest/OldContinuation;)V"));
    assert!(unresolved.contains("\tchanged_prototype\t"));
    assert!(unresolved.contains("Ltest/RangeApi;->submit(Ltest/NewContinuation;)V"));
}

#[test]
fn ignores_platform_references_unless_explicitly_included() {
    let temp = tempdir().expect("temp dir");
    let target = temp.path().join("target.apk");
    let source = temp.path().join("bridge.dex");
    let report = temp.path().join("report");
    let included_report = temp.path().join("included-report");
    write_zip_apk(
        &target,
        &[(
            "classes.dex",
            &build_dex(&[ClassSpec::new("Ltest/Placeholder;")]),
        )],
    );
    fs::write(
        &source,
        source_dex(vec![Instruction::ConstClass(
            "Ljava/lang/String;".to_string(),
        )]),
    )
    .expect("source dex");

    let mut default = audit_command(&target, &report);
    default.arg("--references").arg(&source);
    default.assert().success();
    let summary = read_report(&report, "summary.txt");
    assert!(summary.contains("references_excluded: 1"));
    assert!(summary.contains("unresolved_references: 0"));

    let mut included = audit_command(&target, &included_report);
    included
        .arg("--references")
        .arg(&source)
        .args(["--include-prefix", "Ljava/"]);
    included.assert().failure();
    let unresolved = read_report(&included_report, "unresolved-refs.tsv");
    assert!(unresolved.contains("Ljava/lang/String;\tmissing_owner"));
}

#[test]
fn audits_class_types_embedded_in_member_references() {
    let temp = tempdir().expect("temp dir");
    let target = temp.path().join("target.apk");
    let source = temp.path().join("bridge.dex");
    let report = temp.path().join("report");
    let parameter = "Lmissing/Parameter;";
    let dependency = "Lmissing/Dependency;";
    let classes = [ClassSpec::new(TARGET)
        .with_method(MethodSpec::virtual_method(method_ref(
            TARGET,
            "accept",
            &[parameter],
            "V",
        )))
        .with_field(FieldSpec::instance(field_ref(
            TARGET,
            "dependency",
            dependency,
        )))];
    write_zip_apk(&target, &[("classes.dex", &build_dex(&classes))]);
    fs::write(
        &source,
        source_dex(vec![
            Instruction::InvokeVirtual(method_ref(TARGET, "accept", &[parameter], "V")),
            Instruction::ReadInstanceField(field_ref(TARGET, "dependency", dependency)),
        ]),
    )
    .expect("source dex");

    let mut command = audit_command(&target, &report);
    command.arg("--references").arg(&source);
    command.assert().failure();

    let unresolved = read_report(&report, "unresolved-refs.tsv");
    assert!(unresolved.contains("class\tLmissing/Parameter;\tmissing_owner"));
    assert!(unresolved.contains("class\tLmissing/Dependency;\tmissing_owner"));
    assert!(read_report(&report, "summary.txt").contains("unresolved_references: 2"));
}

#[test]
fn accepts_apk_apks_apkm_and_split_directory_targets() {
    let temp = tempdir().expect("temp dir");
    let source = temp.path().join("bridge.dex");
    let target_dex = build_dex(&compatibility_classes());
    fs::write(
        &source,
        source_dex(vec![Instruction::InvokeVirtual(method_ref(
            TARGET,
            "ok",
            &[],
            "V",
        ))]),
    )
    .expect("source dex");

    let apk = temp.path().join("target.apk");
    write_zip_apk(&apk, &[("classes.dex", &target_dex)]);
    let apk_bytes = fs::read(&apk).expect("apk bytes");

    let apks = temp.path().join("target.apks");
    write_zip_apk(&apks, &[("base.apk", &apk_bytes)]);
    let apkm = temp.path().join("target.apkm");
    write_zip_apk(&apkm, &[("base.apk", &apk_bytes)]);
    let split_directory = temp.path().join("splits");
    fs::create_dir(&split_directory).expect("split directory");
    write_zip_apk(
        &split_directory.join("base.apk"),
        &[("classes.dex", &target_dex)],
    );

    for (index, target) in [apk, apks, apkm, split_directory].iter().enumerate() {
        let report = temp.path().join(format!("report-{index}"));
        let mut command = audit_command(target, &report);
        command.arg("--references").arg(&source);
        command.assert().success();
        assert!(read_report(&report, "summary.txt").contains("status: PASS"));
    }
}

fn compatibility_classes() -> Vec<ClassSpec> {
    vec![
        ClassSpec::new(BASE)
            .with_method(MethodSpec::direct_method(method_ref(
                BASE,
                "<init>",
                &[],
                "V",
            )))
            .with_method(MethodSpec::virtual_method(method_ref(
                BASE,
                "inherited",
                &[],
                "V",
            )))
            .with_method(MethodSpec::static_method(method_ref(
                BASE,
                "inheritedStatic",
                &[],
                "V",
            )))
            .with_field(FieldSpec::instance(field_ref(BASE, "value", "I")))
            .with_field(FieldSpec::static_field(field_ref(BASE, "staticFlag", "I"))),
        ClassSpec::interface(CONTRACT).with_method(MethodSpec::abstract_virtual(method_ref(
            CONTRACT,
            "work",
            &[],
            "V",
        ))),
        ClassSpec::new(TARGET)
            .with_superclass(BASE)
            .with_interface(CONTRACT)
            .with_method(MethodSpec::virtual_method(method_ref(
                TARGET,
                "ok",
                &[],
                "V",
            )))
            .with_method(MethodSpec::virtual_method(method_ref(
                TARGET,
                "changed",
                &["I"],
                "V",
            )))
            .with_field(FieldSpec::instance(field_ref(TARGET, "changed", "I")))
            .with_field(FieldSpec::instance(field_ref(TARGET, "ownValue", "I"))),
    ]
}

fn source_dex(instructions: Vec<Instruction>) -> Vec<u8> {
    build_dex(&[ClassSpec::new(SOURCE).without_superclass().with_method(
        MethodSpec::static_with_code(method_ref(SOURCE, "run", &[], "V"), instructions),
    )])
}

fn method_ref(owner: &str, name: &str, parameters: &[&str], return_type: &str) -> MethodRef {
    MethodRef::new(owner, name, parameters, return_type)
}

fn field_ref(owner: &str, name: &str, field_type: &str) -> FieldRef {
    FieldRef::new(owner, name, field_type)
}

fn audit_command(target: &Path, output: &Path) -> Command {
    let mut command = Command::cargo_bin("unoc-rs").expect("binary exists");
    command
        .arg("audit-refs")
        .arg(target)
        .arg("--no-progress")
        .arg("-o")
        .arg(output);
    command
}

fn read_report(output: &Path, name: &str) -> String {
    fs::read_to_string(output.join(name)).expect("audit report")
}
