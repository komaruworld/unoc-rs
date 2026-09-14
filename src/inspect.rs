use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::apk::{read_apk_part, read_apk_part_bytes};
use crate::cli::InspectConfig;
use crate::dex::parse_dex;
use crate::error::Result;
use crate::input::{resolve_app_input, InputKind};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectReport {
    pub input_path: PathBuf,
    pub input_kind: InputKind,
    pub parts: Vec<InspectPartReport>,
    pub totals: InspectTotals,
    pub warning_count: usize,
    pub warnings: Vec<String>,
    pub unresolved: Vec<InspectIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectPartReport {
    pub part_name: String,
    pub path: Option<PathBuf>,
    pub package_name: Option<String>,
    pub dex_files: Vec<InspectDexReport>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectDexReport {
    pub apk_part: String,
    pub dex_file: String,
    pub dex_index: usize,
    pub bytes: usize,
    pub parsed: bool,
    pub version: Option<String>,
    pub strings: usize,
    pub types: usize,
    pub protos: usize,
    pub fields: usize,
    pub methods: usize,
    pub classes: usize,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InspectTotals {
    pub parts: usize,
    pub readable_parts: usize,
    pub dex_files: usize,
    pub parsed_dex_files: usize,
    pub failed_dex_files: usize,
    pub strings: usize,
    pub types: usize,
    pub protos: usize,
    pub fields: usize,
    pub methods: usize,
    pub classes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectIssue {
    pub apk_part: String,
    pub dex_file: Option<String>,
    pub message: String,
}

pub fn run(config: InspectConfig) -> Result<()> {
    let progress = crate::progress::Progress::new(config.progress);
    let mut progress = progress;
    progress.set_total(4);
    progress.stage_stats(
        "resolve input",
        format!("output: {}", config.output.display()),
    );

    let resolved = resolve_app_input(&config.input)?;
    progress.stage_stats("resolve input", format!("parts={}", resolved.parts.len()));
    let mut report = InspectReport {
        input_path: resolved.source_path.clone(),
        input_kind: resolved.kind,
        parts: Vec::new(),
        totals: InspectTotals {
            parts: resolved.parts.len(),
            ..InspectTotals::default()
        },
        warning_count: 0,
        warnings: Vec::new(),
        unresolved: Vec::new(),
    };

    for part in resolved.parts {
        let mut part_report = InspectPartReport {
            part_name: part.part_name.clone(),
            path: part.path.clone(),
            package_name: None,
            dex_files: Vec::new(),
            error: None,
        };

        match read_apk_part_from_resolved(&resolved.source_path, part) {
            Ok(apk) => {
                report.totals.readable_parts += 1;
                part_report.package_name = apk.package_name;
                for dex in apk.dex_files {
                    let mut dex_report = InspectDexReport {
                        apk_part: dex.apk_part,
                        dex_file: dex.name,
                        dex_index: dex.dex_index,
                        bytes: dex.bytes.len(),
                        parsed: false,
                        version: None,
                        strings: 0,
                        types: 0,
                        protos: 0,
                        fields: 0,
                        methods: 0,
                        classes: 0,
                        error: None,
                    };
                    report.totals.dex_files += 1;

                    match parse_dex(&dex.bytes) {
                        Ok(parsed) => {
                            dex_report.parsed = true;
                            dex_report.version = Some(parsed.raw.header.version);
                            dex_report.strings = parsed.raw.strings.len();
                            dex_report.types = parsed.raw.types.len();
                            dex_report.protos = parsed.raw.protos.len();
                            dex_report.fields = parsed.raw.fields.len();
                            dex_report.methods = parsed.raw.methods.len();
                            dex_report.classes = parsed.raw.classes.len();

                            report.totals.parsed_dex_files += 1;
                            report.totals.strings += dex_report.strings;
                            report.totals.types += dex_report.types;
                            report.totals.protos += dex_report.protos;
                            report.totals.fields += dex_report.fields;
                            report.totals.methods += dex_report.methods;
                            report.totals.classes += dex_report.classes;
                        }
                        Err(error) => {
                            let message = error.to_string();
                            report.totals.failed_dex_files += 1;
                            report.unresolved.push(InspectIssue {
                                apk_part: dex_report.apk_part.clone(),
                                dex_file: Some(dex_report.dex_file.clone()),
                                message: message.clone(),
                            });
                            dex_report.error = Some(message);
                        }
                    }

                    part_report.dex_files.push(dex_report);
                }
            }
            Err(error) => {
                let message = error.to_string();
                report.unresolved.push(InspectIssue {
                    apk_part: part_report.part_name.clone(),
                    dex_file: None,
                    message: message.clone(),
                });
                part_report.error = Some(message);
            }
        }

        report.parts.push(part_report);
    }

    report.warnings = report
        .unresolved
        .iter()
        .map(|issue| {
            let dex = issue.dex_file.as_deref().unwrap_or("-");
            format!("{}!{}: {}", issue.apk_part, dex, issue.message)
        })
        .collect();
    report.warning_count = report.warnings.len();

    progress.stage_stats(
        "parse dex",
        format!(
            "dex files={}, parsed classes={}",
            report.totals.dex_files, report.totals.classes
        ),
    );

    progress.stage_stats("report", format!("writing to {}", config.output.display()));
    fs::create_dir_all(&config.output)?;
    fs::write(
        config.output.join("inspect.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    fs::write(
        config.output.join("inspect-summary.txt"),
        render_summary(&report),
    )?;
    Ok(())
}

fn read_apk_part_from_resolved(
    source_path: &std::path::Path,
    part: crate::input::ApkPart,
) -> Result<crate::apk::ApkInput> {
    if let Some(path) = part.path {
        read_apk_part(&path, &part.part_name)
    } else {
        read_apk_part_bytes(source_path, &part.part_name, part.bytes)
    }
}

fn render_summary(report: &InspectReport) -> String {
    let mut output = String::new();
    output.push_str("unoc-rs Inspect Report\n");
    output.push_str("======================\n\n");
    output.push_str(&format!("Input: {}\n", report.input_path.display()));
    output.push_str(&format!("Kind: {:?}\n", report.input_kind));
    output.push_str(&format!("Parts: {}\n", report.totals.parts));
    output.push_str(&format!(
        "Readable parts: {}\n",
        report.totals.readable_parts
    ));
    output.push_str(&format!("DEX files: {}\n", report.totals.dex_files));
    output.push_str(&format!("Parsed DEX: {}\n", report.totals.parsed_dex_files));
    output.push_str(&format!("Failed DEX: {}\n", report.totals.failed_dex_files));
    output.push_str(&format!("warnings: {}\n", report.warning_count));
    output.push_str(&format!("Classes: {}\n", report.totals.classes));
    output.push_str(&format!("Methods: {}\n", report.totals.methods));
    output.push_str(&format!("Fields: {}\n", report.totals.fields));
    output.push('\n');

    for part in &report.parts {
        output.push_str(&format!("Part: {}\n", part.part_name));
        if let Some(path) = &part.path {
            output.push_str(&format!("  Path: {}\n", path.display()));
        }
        if let Some(package_name) = &part.package_name {
            output.push_str(&format!("  Package: {package_name}\n"));
        }
        if let Some(error) = &part.error {
            output.push_str(&format!("  Error: {error}\n"));
        }
        for dex in &part.dex_files {
            output.push_str(&format!(
                "  - {} #{}: {} bytes, parsed={}, classes={}, methods={}, fields={}\n",
                dex.dex_file,
                dex.dex_index,
                dex.bytes,
                dex.parsed,
                dex.classes,
                dex.methods,
                dex.fields
            ));
            if let Some(error) = &dex.error {
                output.push_str(&format!("    Error: {error}\n"));
            }
        }
        output.push('\n');
    }

    output.push_str("Unresolved\n");
    output.push_str("----------\n");
    if report.unresolved.is_empty() {
        output.push_str("none\n");
    } else {
        for issue in &report.unresolved {
            let dex = issue.dex_file.as_deref().unwrap_or("-");
            output.push_str(&format!("{}!{}: {}\n", issue.apk_part, dex, issue.message));
        }
    }
    output
}
