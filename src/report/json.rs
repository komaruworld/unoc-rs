use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::matcher::ClassMatch;
use crate::model::DexOrigin;
use crate::report::ReportBundle;

pub const MAPPING_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Deserialize)]
pub struct MappingReport {
    #[serde(default)]
    pub schema_version: u32,
    pub old_app: MappingApp,
    pub new_app: MappingApp,
    pub matches: MappingMatches,
    pub min_confidence: f32,
    pub low_confidence: f32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MappingApp {
    pub apk_name: String,
    pub package_name: Option<String>,
    pub classes: Vec<MappingClass>,
    pub coverage: MappingCoverage,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MappingClass {
    pub id: usize,
    pub descriptor: String,
    pub origin: DexOrigin,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct MappingCoverage {
    #[serde(default)]
    pub apk_parts: usize,
    #[serde(default)]
    pub dex_files: usize,
    #[serde(default)]
    pub parsed_classes: usize,
    #[serde(default)]
    pub parsed_methods: usize,
    #[serde(default)]
    pub parsed_fields: usize,
    #[serde(default)]
    pub warning_count: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MappingMatches {
    pub classes: Vec<ClassMatch>,
    #[serde(default)]
    pub method_count: usize,
    #[serde(default)]
    pub field_count: usize,
}

impl MappingApp {
    pub fn class_label(&self, id: Option<usize>) -> String {
        let Some(id) = id else {
            return String::new();
        };
        let Some(class) = self.classes.iter().find(|class| class.id == id) else {
            return format!("#{id}");
        };
        let class_index = class
            .origin
            .class_def_index
            .map(|index| index.to_string())
            .unwrap_or_else(|| "?".to_string());
        format!(
            "{} ({}!{}#{})",
            class.descriptor, class.origin.apk_part, class.origin.dex_file, class_index
        )
    }
}

#[derive(Serialize)]
struct MappingReportView<'a> {
    schema_version: u32,
    old_app: MappingAppView<'a>,
    new_app: MappingAppView<'a>,
    matches: MappingMatchesView<'a>,
    min_confidence: f32,
    low_confidence: f32,
}

#[derive(Serialize)]
struct MappingAppView<'a> {
    apk_name: &'a str,
    package_name: &'a Option<String>,
    classes: Vec<MappingClassView<'a>>,
    coverage: MappingCoverageView,
}

#[derive(Serialize)]
struct MappingClassView<'a> {
    id: usize,
    descriptor: &'a str,
    origin: &'a DexOrigin,
}

#[derive(Serialize)]
struct MappingCoverageView {
    apk_parts: usize,
    dex_files: usize,
    parsed_classes: usize,
    parsed_methods: usize,
    parsed_fields: usize,
    warning_count: usize,
}

#[derive(Serialize)]
struct MappingMatchesView<'a> {
    classes: &'a [ClassMatch],
    method_count: usize,
    field_count: usize,
}

impl<'a> MappingReportView<'a> {
    fn new(bundle: &'a ReportBundle) -> Self {
        Self {
            schema_version: MAPPING_SCHEMA_VERSION,
            old_app: MappingAppView::new(&bundle.old_app),
            new_app: MappingAppView::new(&bundle.new_app),
            matches: MappingMatchesView {
                classes: &bundle.matches.classes,
                method_count: bundle.matches.methods.len(),
                field_count: bundle.matches.fields.len(),
            },
            min_confidence: bundle.min_confidence,
            low_confidence: bundle.low_confidence,
        }
    }
}

impl<'a> MappingAppView<'a> {
    fn new(app: &'a crate::model::AppModel) -> Self {
        Self {
            apk_name: &app.apk_name,
            package_name: &app.package_name,
            classes: app
                .classes
                .iter()
                .map(|class| MappingClassView {
                    id: class.id,
                    descriptor: &class.descriptor,
                    origin: &class.origin,
                })
                .collect(),
            coverage: MappingCoverageView {
                apk_parts: app.coverage.apk_parts,
                dex_files: app.coverage.dex_files,
                parsed_classes: app.coverage.parsed_classes,
                parsed_methods: app.coverage.parsed_methods,
                parsed_fields: app.coverage.parsed_fields,
                warning_count: app.coverage.warnings.len(),
            },
        }
    }
}

pub fn write_json(bundle: &ReportBundle, path: &Path) -> Result<()> {
    let file = std::fs::File::create(path)?;
    let writer = std::io::BufWriter::new(file);
    write_compact(bundle, writer)
}

pub(crate) fn write_compact<W: Write>(bundle: &ReportBundle, writer: W) -> Result<()> {
    serde_json::to_writer(writer, &MappingReportView::new(bundle))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::matcher::{ClassMatch, MatchReport, MatchStatus};
    use crate::model::{
        AppModel, ClassModel, DexOrigin, MethodCodeSummary, MethodModel, ModelWarning,
        ParseCoverage,
    };
    use crate::report::ReportBundle;

    use super::{write_compact, MappingReport, MAPPING_SCHEMA_VERSION};

    #[test]
    fn compact_mapping_omits_heavy_parser_details() {
        let bundle = rich_bundle();
        let legacy = serde_json::to_vec(&bundle).expect("legacy JSON");
        let mut compact = Vec::new();
        write_compact(&bundle, &mut compact).expect("compact JSON");

        let text = std::str::from_utf8(&compact).expect("UTF-8 JSON");
        assert!(!text.contains("opcode_histogram"));
        assert!(!text.contains("large parser warning"));
        assert!(compact.len() * 2 < legacy.len());

        let report: MappingReport = serde_json::from_slice(&compact).expect("mapping report");
        assert_eq!(report.schema_version, MAPPING_SCHEMA_VERSION);
        assert_eq!(report.old_app.coverage.warning_count, 1);
        assert_eq!(report.matches.method_count, 0);
        assert_eq!(
            report.old_app.class_label(Some(0)),
            "La/Old; (base.apk!classes.dex#7)"
        );
    }

    #[test]
    fn compact_reader_accepts_legacy_report_bundle() {
        let bundle = rich_bundle();
        let legacy = serde_json::to_vec(&bundle).expect("legacy JSON");
        let report: MappingReport = serde_json::from_slice(&legacy).expect("legacy mapping report");

        assert_eq!(report.schema_version, 0);
        assert_eq!(report.old_app.classes[0].descriptor, "La/Old;");
        assert_eq!(report.matches.classes.len(), 1);
    }

    fn rich_bundle() -> ReportBundle {
        let old_class = ClassModel {
            id: 0,
            descriptor: "La/Old;".to_string(),
            access_flags: 1,
            superclass: Some("Ljava/lang/Object;".to_string()),
            interfaces: vec!["Ljava/io/Serializable;".to_string()],
            methods: vec![MethodModel {
                id: 0,
                owner_class: "La/Old;".to_string(),
                name: "run".to_string(),
                return_type: "V".to_string(),
                parameters: Vec::new(),
                access_flags: 1,
                code: Some(MethodCodeSummary {
                    registers_size: 2,
                    ins_size: 1,
                    outs_size: 1,
                    instruction_count: 100,
                    opcode_histogram: BTreeMap::from([(0x1a, 100)]),
                    string_refs: vec!["x".repeat(2_000)],
                    method_refs: vec!["La/Old;->run()->V".repeat(100)],
                    field_refs: Vec::new(),
                    branch_count: 1,
                    return_count: 1,
                    throw_count: 0,
                    switch_count: 0,
                }),
            }],
            fields: Vec::new(),
            origin: DexOrigin {
                apk_part: "base.apk".to_string(),
                dex_file: "classes.dex".to_string(),
                dex_index: 0,
                class_def_index: Some(7),
            },
        };
        let mut new_class = old_class.clone();
        new_class.descriptor = "Lb/New;".to_string();
        new_class.origin.class_def_index = Some(9);
        let coverage = ParseCoverage {
            apk_parts: 1,
            dex_files: 1,
            parsed_classes: 1,
            parsed_methods: 1,
            parsed_fields: 0,
            warnings: vec![ModelWarning {
                origin: "classes.dex".to_string(),
                kind: "Fixture".to_string(),
                message: "large parser warning".repeat(100),
            }],
        };

        ReportBundle {
            old_app: AppModel {
                apk_name: "old.apk".to_string(),
                package_name: Some("example.old".to_string()),
                classes: vec![old_class],
                coverage: coverage.clone(),
            },
            new_app: AppModel {
                apk_name: "new.apk".to_string(),
                package_name: Some("example.new".to_string()),
                classes: vec![new_class],
                coverage,
            },
            matches: MatchReport {
                classes: vec![ClassMatch {
                    old_class_id: Some(0),
                    new_class_id: Some(0),
                    score: 1.0,
                    status: MatchStatus::Matched,
                    reasons: vec!["verified: fixture".to_string()],
                    candidates: Vec::new(),
                }],
                methods: Vec::new(),
                fields: Vec::new(),
            },
            min_confidence: 0.8,
            low_confidence: 0.55,
        }
    }
}
