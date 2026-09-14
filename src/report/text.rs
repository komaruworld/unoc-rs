use std::io::Write;
use std::path::Path;

use crate::error::Result;
use crate::matcher::{
    MatchStatus, CALL_GRAPH_VERIFY_PASSES, RARE_ANCHOR_MAX_FREQUENCY, SEMANTIC_BREAK_CLASS_KIND,
    UNSAFE_SAME_DESCRIPTOR_WEAK_SHAPE, VERIFIED_CALL_GRAPH_NEIGHBORHOOD,
    VERIFIED_EXACT_CLASS_FINGERPRINT, VERIFIED_EXACT_DESCRIPTOR_STABLE_API,
    VERIFIED_EXACT_DESCRIPTOR_STABLE_CODE, VERIFIED_EXACT_DESCRIPTOR_STABLE_PROTO_CODE,
    VERIFIED_RARE_ANCHORS_STABLE_SHAPE, VERIFIED_RENAMED_EXACT_BEHAVIOR,
    VERIFIED_RENAMED_STABLE_PROTO_ANCHOR,
};
use crate::model::{FieldModel, MethodModel};
use crate::report::{ClassLabelIndex, ReportBundle};

pub fn write_summary(bundle: &ReportBundle, path: &Path) -> Result<()> {
    let matched = bundle
        .matches
        .classes
        .iter()
        .filter(|item| item.status == MatchStatus::Matched)
        .count();
    let low = bundle
        .matches
        .classes
        .iter()
        .filter(|item| item.status == MatchStatus::LowConfidence)
        .count();
    let conflicts = bundle
        .matches
        .classes
        .iter()
        .filter(|item| item.status == MatchStatus::Conflict)
        .count();
    let semantic_breaks = bundle
        .matches
        .classes
        .iter()
        .filter(|item| item.status == MatchStatus::SemanticBreak)
        .count();
    let unresolved_old = bundle
        .matches
        .classes
        .iter()
        .filter(|item| item.status == MatchStatus::UnresolvedOld)
        .count();
    let unresolved_new = bundle
        .matches
        .classes
        .iter()
        .filter(|item| item.status == MatchStatus::UnresolvedNew)
        .count();
    let verified_exact = verified_reason_count(bundle, VERIFIED_EXACT_CLASS_FINGERPRINT);
    let verified_api = verified_reason_count(bundle, VERIFIED_EXACT_DESCRIPTOR_STABLE_API);
    let verified_code = verified_reason_count(bundle, VERIFIED_EXACT_DESCRIPTOR_STABLE_CODE);
    let verified_proto_code =
        verified_reason_count(bundle, VERIFIED_EXACT_DESCRIPTOR_STABLE_PROTO_CODE);
    let verified_renamed_exact = verified_reason_count(bundle, VERIFIED_RENAMED_EXACT_BEHAVIOR);
    let verified_renamed_anchor =
        verified_reason_count(bundle, VERIFIED_RENAMED_STABLE_PROTO_ANCHOR);
    let verified_rare_anchor = verified_reason_count(bundle, VERIFIED_RARE_ANCHORS_STABLE_SHAPE);
    let verified_call_graph = verified_reason_count(bundle, VERIFIED_CALL_GRAPH_NEIGHBORHOOD);
    let text = format!(
        "old_apk: {}\nnew_apk: {}\nold_classes: {}\nnew_classes: {}\nold_apk_parts: {}\nnew_apk_parts: {}\nold_dex_files: {}\nnew_dex_files: {}\nold_warnings: {}\nnew_warnings: {}\nmatched_classes: {}\nlow_confidence_classes: {}\nconflict_classes: {}\nsemantic_break_classes: {}\nunresolved_old_classes: {}\nunresolved_new_classes: {}\nverified_exact_class_fingerprint: {}\nverified_exact_descriptor_stable_api_shape: {}\nverified_exact_descriptor_stable_code_pattern: {}\nverified_exact_descriptor_stable_proto_code_pattern: {}\nverified_renamed_exact_behavior_pattern: {}\nverified_renamed_stable_prototype_anchor_pattern: {}\nverified_rare_anchors_stable_shape: {}\nverified_call_graph_neighborhood: {}\ncall_graph_verify_passes: {}\nrare_anchor_max_frequency: {}\nmin_confidence: {:.2}\nlow_confidence: {:.2}\n",
        bundle.old_app.apk_name,
        bundle.new_app.apk_name,
        bundle.old_app.classes.len(),
        bundle.new_app.classes.len(),
        bundle.old_app.coverage.apk_parts,
        bundle.new_app.coverage.apk_parts,
        bundle.old_app.coverage.dex_files,
        bundle.new_app.coverage.dex_files,
        bundle.old_app.coverage.warnings.len(),
        bundle.new_app.coverage.warnings.len(),
        matched,
        low,
        conflicts,
        semantic_breaks,
        unresolved_old,
        unresolved_new,
        verified_exact,
        verified_api,
        verified_code,
        verified_proto_code,
        verified_renamed_exact,
        verified_renamed_anchor,
        verified_rare_anchor,
        verified_call_graph,
        CALL_GRAPH_VERIFY_PASSES,
        RARE_ANCHOR_MAX_FREQUENCY,
        bundle.min_confidence,
        bundle.low_confidence
    );
    std::fs::write(path, text)?;
    Ok(())
}

pub fn write_tiered_mappings(bundle: &ReportBundle, output_dir: &Path) -> Result<()> {
    let old_labels = ClassLabelIndex::new(&bundle.old_app);
    let new_labels = ClassLabelIndex::new(&bundle.new_app);
    write_tier_file(
        bundle,
        &output_dir.join("verified.txt"),
        &old_labels,
        &new_labels,
        |item| item.status == MatchStatus::Matched && is_verified(item),
    )?;
    write_tier_file(
        bundle,
        &output_dir.join("name-only.txt"),
        &old_labels,
        &new_labels,
        |item| {
            matches!(
                item.status,
                MatchStatus::Matched | MatchStatus::LowConfidence
            ) && is_same_descriptor_name_only(item)
        },
    )?;
    write_tier_file(
        bundle,
        &output_dir.join("unsafe.txt"),
        &old_labels,
        &new_labels,
        |item| {
            matches!(
                item.status,
                MatchStatus::Conflict | MatchStatus::SemanticBreak
            ) || item.reasons.iter().any(|reason| {
                reason == SEMANTIC_BREAK_CLASS_KIND || reason == UNSAFE_SAME_DESCRIPTOR_WEAK_SHAPE
            })
        },
    )?;
    Ok(())
}

pub fn write_member_mappings(bundle: &ReportBundle, output_dir: &Path) -> Result<()> {
    if !bundle.matches.methods.is_empty() {
        write_method_tsv(bundle, &output_dir.join("methods.tsv"))?;
    }
    if !bundle.matches.fields.is_empty() {
        write_field_tsv(bundle, &output_dir.join("fields.tsv"))?;
    }
    Ok(())
}

fn write_method_tsv(bundle: &ReportBundle, path: &Path) -> Result<()> {
    let file = std::fs::File::create(path)?;
    let mut out = std::io::BufWriter::new(file);
    let old_methods = method_index(&bundle.old_app);
    let new_methods = method_index(&bundle.new_app);
    let old_classes = ClassLabelIndex::new(&bundle.old_app);
    let new_classes = ClassLabelIndex::new(&bundle.new_app);
    writeln!(
        out,
        "old_class\told_method\tnew_class\tnew_method\tscore\tstatus\treasons"
    )?;
    for item in &bundle.matches.methods {
        writeln!(
            out,
            "{}\t{}\t{}\t{}\t{:.2}\t{:?}\t{}",
            old_classes.label(item.old_owner_class_id),
            item.old_member_id
                .and_then(|id| old_methods.get(&id))
                .map(|method| method_signature(method))
                .unwrap_or_default(),
            new_classes.label(item.new_owner_class_id),
            item.new_member_id
                .and_then(|id| new_methods.get(&id))
                .map(|method| method_signature(method))
                .unwrap_or_default(),
            item.score,
            item.status,
            item.reasons.join("; ")
        )?;
    }
    Ok(())
}

fn write_field_tsv(bundle: &ReportBundle, path: &Path) -> Result<()> {
    let file = std::fs::File::create(path)?;
    let mut out = std::io::BufWriter::new(file);
    let old_fields = field_index(&bundle.old_app);
    let new_fields = field_index(&bundle.new_app);
    let old_classes = ClassLabelIndex::new(&bundle.old_app);
    let new_classes = ClassLabelIndex::new(&bundle.new_app);
    writeln!(
        out,
        "old_class\told_field\tnew_class\tnew_field\tscore\tstatus\treasons"
    )?;
    for item in &bundle.matches.fields {
        writeln!(
            out,
            "{}\t{}\t{}\t{}\t{:.2}\t{:?}\t{}",
            old_classes.label(item.old_owner_class_id),
            item.old_member_id
                .and_then(|id| old_fields.get(&id))
                .map(|field| field_signature(field))
                .unwrap_or_default(),
            new_classes.label(item.new_owner_class_id),
            item.new_member_id
                .and_then(|id| new_fields.get(&id))
                .map(|field| field_signature(field))
                .unwrap_or_default(),
            item.score,
            item.status,
            item.reasons.join("; ")
        )?;
    }
    Ok(())
}

fn method_index(app: &crate::model::AppModel) -> std::collections::BTreeMap<usize, &MethodModel> {
    app.classes
        .iter()
        .flat_map(|class| class.methods.iter().map(|method| (method.id, method)))
        .collect()
}

fn field_index(app: &crate::model::AppModel) -> std::collections::BTreeMap<usize, &FieldModel> {
    app.classes
        .iter()
        .flat_map(|class| class.fields.iter().map(|field| (field.id, field)))
        .collect()
}

fn method_signature(method: &MethodModel) -> String {
    format!(
        "{}({})->{}",
        method.name,
        method.parameters.join(","),
        method.return_type
    )
}

fn field_signature(field: &FieldModel) -> String {
    format!("{}:{}", field.name, field.field_type)
}

fn write_tier_file(
    bundle: &ReportBundle,
    path: &Path,
    old_labels: &ClassLabelIndex,
    new_labels: &ClassLabelIndex,
    include: impl Fn(&crate::matcher::ClassMatch) -> bool,
) -> Result<()> {
    let file = std::fs::File::create(path)?;
    let mut out = std::io::BufWriter::new(file);
    writeln!(out, "old\tnew\tscore\tstatus\treasons")?;
    for item in bundle.matches.classes.iter().filter(|item| include(item)) {
        writeln!(
            out,
            "{}\t{}\t{:.2}\t{:?}\t{}",
            old_labels.label(item.old_class_id),
            new_labels.label(item.new_class_id),
            item.score,
            item.status,
            item.reasons.join("; ")
        )?;
    }
    Ok(())
}

fn is_verified(item: &crate::matcher::ClassMatch) -> bool {
    item.reasons
        .iter()
        .any(|reason| reason.starts_with("verified:"))
}

fn is_same_descriptor_name_only(item: &crate::matcher::ClassMatch) -> bool {
    item.reasons
        .iter()
        .any(|reason| reason == "same descriptor")
        && !is_verified(item)
}

fn verified_reason_count(bundle: &ReportBundle, reason: &str) -> usize {
    bundle
        .matches
        .classes
        .iter()
        .filter(|item| item.reasons.iter().any(|item_reason| item_reason == reason))
        .count()
}

pub fn write_mapping(
    bundle: &ReportBundle,
    path: &Path,
    max_rows_per_section: Option<usize>,
) -> Result<()> {
    let file = std::fs::File::create(path)?;
    let mut out = std::io::BufWriter::new(file);
    let old_labels = ClassLabelIndex::new(&bundle.old_app);
    let new_labels = ClassLabelIndex::new(&bundle.new_app);
    for (index, section) in class_sections().into_iter().enumerate() {
        if index > 0 {
            writeln!(out)?;
        }
        writeln!(out, "{}", section.title)?;
        write_class_rows(
            &mut out,
            bundle,
            &old_labels,
            &new_labels,
            section.status,
            max_rows_per_section,
        )?;
    }

    Ok(())
}

pub fn write_mapping_chunks(
    bundle: &ReportBundle,
    output_dir: &Path,
    max_rows_per_section: Option<usize>,
    chunk_rows: Option<usize>,
) -> Result<()> {
    cleanup_mapping_chunks(output_dir)?;

    let Some(preview_limit) = max_rows_per_section else {
        return Ok(());
    };
    let Some(chunk_rows) = chunk_rows else {
        return Ok(());
    };
    if chunk_rows == 0 {
        return Ok(());
    }

    let old_labels = ClassLabelIndex::new(&bundle.old_app);
    let new_labels = ClassLabelIndex::new(&bundle.new_app);
    let sections = class_sections();
    let totals = sections
        .iter()
        .map(|section| class_row_count(bundle, section.status))
        .collect::<Vec<_>>();

    if !totals.iter().any(|total| *total > preview_limit) {
        return Ok(());
    }

    let parts_dir = output_dir.join("mapping-parts");
    std::fs::create_dir_all(&parts_dir)?;

    let index_file = std::fs::File::create(output_dir.join("mapping-index.txt"))?;
    let mut index = std::io::BufWriter::new(index_file);
    writeln!(index, "unoc-rs MAPPING INDEX")?;
    writeln!(index, "preview: mapping.txt")?;
    writeln!(index, "parts_dir: mapping-parts")?;
    writeln!(index, "chunk_rows: {chunk_rows}")?;
    writeln!(index, "old_apk: {}", bundle.old_app.apk_name)?;
    writeln!(index, "new_apk: {}", bundle.new_app.apk_name)?;
    writeln!(index)?;

    for (section, total) in sections.iter().zip(totals) {
        writeln!(index, "{}: {total} rows", section.title)?;
        if total == 0 {
            writeln!(index)?;
            continue;
        }

        let mut chunk_index = 0usize;
        let mut chunk_out: Option<std::io::BufWriter<std::fs::File>> = None;

        for (row_index, item) in bundle
            .matches
            .classes
            .iter()
            .filter(|item| item.status == section.status)
            .enumerate()
        {
            if row_index.is_multiple_of(chunk_rows) {
                if let Some(mut out) = chunk_out.take() {
                    out.flush()?;
                }
                chunk_index += 1;
                let start = row_index + 1;
                let end = (row_index + chunk_rows).min(total);
                let file_name = format!("{}-{chunk_index:04}.txt", section.slug);
                writeln!(
                    index,
                    "  mapping-parts/{file_name}: rows {start}-{end} of {total}"
                )?;

                let file = std::fs::File::create(parts_dir.join(file_name))?;
                let mut out = std::io::BufWriter::new(file);
                writeln!(out, "{}", section.title)?;
                writeln!(out, "rows {start}-{end} of {total}")?;
                writeln!(out, "old_apk: {}", bundle.old_app.apk_name)?;
                writeln!(out, "new_apk: {}", bundle.new_app.apk_name)?;
                writeln!(out)?;
                chunk_out = Some(out);
            }

            if let Some(out) = chunk_out.as_mut() {
                write_class_row(out, item, &old_labels, &new_labels)?;
            }
        }
        if let Some(mut out) = chunk_out.take() {
            out.flush()?;
        }
        writeln!(index)?;
    }

    Ok(())
}

fn cleanup_mapping_chunks(output_dir: &Path) -> Result<()> {
    let index_path = output_dir.join("mapping-index.txt");
    if index_path.exists() {
        std::fs::remove_file(index_path)?;
    }

    let parts_dir = output_dir.join("mapping-parts");
    if parts_dir.is_dir() {
        std::fs::remove_dir_all(parts_dir)?;
    } else if parts_dir.exists() {
        std::fs::remove_file(parts_dir)?;
    }
    Ok(())
}

fn write_class_rows(
    out: &mut dyn Write,
    bundle: &ReportBundle,
    old_labels: &ClassLabelIndex,
    new_labels: &ClassLabelIndex,
    status: MatchStatus,
    max_rows: Option<usize>,
) -> Result<()> {
    let total = class_row_count(bundle, status);
    let limit = max_rows.unwrap_or(total);
    for item in bundle
        .matches
        .classes
        .iter()
        .filter(|item| item.status == status)
        .take(limit)
    {
        write_class_row(out, item, old_labels, new_labels)?;
    }
    if total > limit {
        writeln!(
            out,
            "... truncated: showing {limit} of {total} rows; full rows are in mapping-index.txt when chunking is enabled; use --max-txt-rows 0 for one full TXT"
        )?;
    }
    Ok(())
}

fn write_class_row(
    out: &mut dyn Write,
    item: &crate::matcher::ClassMatch,
    old_labels: &ClassLabelIndex,
    new_labels: &ClassLabelIndex,
) -> Result<()> {
    match item.status {
        MatchStatus::Matched
        | MatchStatus::LowConfidence
        | MatchStatus::Conflict
        | MatchStatus::SemanticBreak => {
            if item.status != MatchStatus::Matched {
                writeln!(out, "# UNSAFE: {:?}", item.status)?;
            }
            let old_label = old_labels.label(item.old_class_id);
            let new_label = new_labels.label(item.new_class_id);
            writeln!(out, "[{:.2}] {old_label} -> {new_label}", item.score)?;
            if !item.reasons.is_empty() {
                writeln!(out, "  reasons: {}", item.reasons.join(", "))?;
            }
        }
        MatchStatus::UnresolvedOld => {
            let old_label = old_labels.label(item.old_class_id);
            writeln!(out, "{old_label}: {}", item.reasons.join(", "))?;
        }
        MatchStatus::UnresolvedNew => {
            let new_label = new_labels.label(item.new_class_id);
            writeln!(out, "{new_label}: {}", item.reasons.join(", "))?;
        }
    }
    Ok(())
}

fn class_row_count(bundle: &ReportBundle, status: MatchStatus) -> usize {
    bundle
        .matches
        .classes
        .iter()
        .filter(|item| item.status == status)
        .count()
}

#[derive(Debug, Clone, Copy)]
struct ClassSection {
    status: MatchStatus,
    title: &'static str,
    slug: &'static str,
}

fn class_sections() -> [ClassSection; 6] {
    [
        ClassSection {
            status: MatchStatus::Matched,
            title: "MATCHED CLASSES",
            slug: "matched-classes",
        },
        ClassSection {
            status: MatchStatus::LowConfidence,
            title: "LOW CONFIDENCE CLASSES",
            slug: "low-confidence-classes",
        },
        ClassSection {
            status: MatchStatus::Conflict,
            title: "CONFLICTS",
            slug: "conflicts",
        },
        ClassSection {
            status: MatchStatus::SemanticBreak,
            title: "SEMANTIC BREAKS",
            slug: "semantic-breaks",
        },
        ClassSection {
            status: MatchStatus::UnresolvedOld,
            title: "UNRESOLVED OLD CLASSES",
            slug: "unresolved-old-classes",
        },
        ClassSection {
            status: MatchStatus::UnresolvedNew,
            title: "UNRESOLVED NEW CLASSES",
            slug: "unresolved-new-classes",
        },
    ]
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use crate::matcher::{Candidate, ClassMatch, MatchReport, MatchStatus};
    use crate::model::{AppModel, ClassModel, DexOrigin, ModelWarning, ParseCoverage};
    use crate::report::{
        text::write_mapping, text::write_mapping_chunks, text::write_summary, ReportBundle,
    };

    #[test]
    fn mapping_report_includes_dex_origins() {
        let temp = tempdir().expect("temp dir");
        let bundle = ReportBundle {
            old_app: app_with_class(1, "La/b/C;", "classes2.dex", 143),
            new_app: app_with_class(2, "Lx/y/Z;", "classes3.dex", 88),
            matches: MatchReport {
                classes: vec![ClassMatch {
                    old_class_id: Some(1),
                    new_class_id: Some(2),
                    score: 0.96,
                    status: MatchStatus::Matched,
                    reasons: vec!["same superclass".to_string()],
                    candidates: vec![Candidate {
                        entity_id: 2,
                        score: 0.96,
                        reasons: vec!["same superclass".to_string()],
                    }],
                }],
                methods: Vec::new(),
                fields: Vec::new(),
            },
            min_confidence: 0.80,
            low_confidence: 0.55,
        };

        let path = temp.path().join("mapping.txt");
        write_mapping(&bundle, &path, None).expect("mapping");
        let mapping = std::fs::read_to_string(path).expect("mapping text");
        assert!(mapping.contains("classes2.dex#143"));
        assert!(mapping.contains("classes3.dex#88"));
    }

    #[test]
    fn summary_includes_warning_count() {
        let temp = tempdir().expect("temp dir");
        let mut app = app_with_class(1, "La/B;", "base.apk", 0);
        app.coverage.warnings.push(ModelWarning {
            origin: "base.apk!classes.dex".to_string(),
            kind: "CodeItem".to_string(),
            message: "bad code item".to_string(),
        });
        let bundle = ReportBundle {
            old_app: app,
            new_app: app_with_class(2, "La/B;", "base.apk", 0),
            matches: MatchReport {
                classes: Vec::new(),
                methods: Vec::new(),
                fields: Vec::new(),
            },
            min_confidence: 0.80,
            low_confidence: 0.55,
        };

        let path = temp.path().join("summary.txt");
        write_summary(&bundle, &path).expect("summary");
        let summary = std::fs::read_to_string(path).expect("summary text");
        assert!(summary.contains("old_warnings: 1"));
    }

    #[test]
    fn mapping_report_can_truncate_large_sections() {
        let temp = tempdir().expect("temp dir");
        let bundle = ReportBundle {
            old_app: app_with_class(1, "La/B;", "base.apk", 0),
            new_app: app_with_class(2, "La/B;", "base.apk", 0),
            matches: MatchReport {
                classes: vec![
                    ClassMatch {
                        old_class_id: Some(1),
                        new_class_id: Some(2),
                        score: 0.99,
                        status: MatchStatus::Matched,
                        reasons: Vec::new(),
                        candidates: Vec::new(),
                    },
                    ClassMatch {
                        old_class_id: Some(1),
                        new_class_id: Some(2),
                        score: 0.98,
                        status: MatchStatus::Matched,
                        reasons: Vec::new(),
                        candidates: Vec::new(),
                    },
                ],
                methods: Vec::new(),
                fields: Vec::new(),
            },
            min_confidence: 0.80,
            low_confidence: 0.55,
        };

        let path = temp.path().join("mapping.txt");
        write_mapping(&bundle, &path, Some(1)).expect("mapping");
        let mapping = std::fs::read_to_string(path).expect("mapping text");
        assert!(mapping.contains("truncated: showing 1 of 2 rows"));
    }

    #[test]
    fn mapping_chunks_keep_full_rows_when_preview_is_truncated() {
        let temp = tempdir().expect("temp dir");
        let bundle = ReportBundle {
            old_app: app_with_class(1, "La/B;", "base.apk", 0),
            new_app: app_with_class(2, "La/B;", "base.apk", 0),
            matches: MatchReport {
                classes: vec![class_match(0.99), class_match(0.98), class_match(0.97)],
                methods: Vec::new(),
                fields: Vec::new(),
            },
            min_confidence: 0.80,
            low_confidence: 0.55,
        };

        write_mapping_chunks(&bundle, temp.path(), Some(1), Some(2)).expect("chunks");
        let index_path = temp.path().join("mapping-index.txt");
        let index = std::fs::read_to_string(&index_path).expect("index");
        assert!(index.contains("mapping-parts/matched-classes-0001.txt"));
        assert!(index.contains("mapping-parts/matched-classes-0002.txt"));

        let second_chunk = std::fs::read_to_string(
            temp.path()
                .join("mapping-parts")
                .join("matched-classes-0002.txt"),
        )
        .expect("second chunk");
        assert!(second_chunk.contains("[0.97]"));

        write_mapping_chunks(&bundle, temp.path(), Some(10), Some(2)).expect("cleanup chunks");
        assert!(!index_path.exists());
        assert!(!temp.path().join("mapping-parts").exists());
    }

    fn class_match(score: f32) -> ClassMatch {
        ClassMatch {
            old_class_id: Some(1),
            new_class_id: Some(2),
            score,
            status: MatchStatus::Matched,
            reasons: Vec::new(),
            candidates: Vec::new(),
        }
    }

    fn app_with_class(
        id: usize,
        descriptor: &str,
        dex_file: &str,
        class_def_index: usize,
    ) -> AppModel {
        AppModel {
            apk_name: "app.apk".to_string(),
            package_name: None,
            classes: vec![ClassModel {
                id,
                descriptor: descriptor.to_string(),
                access_flags: 1,
                superclass: None,
                interfaces: Vec::new(),
                methods: Vec::new(),
                fields: Vec::new(),
                origin: DexOrigin {
                    apk_part: dex_file.to_string(),
                    dex_file: dex_file.to_string(),
                    dex_index: 0,
                    class_def_index: Some(class_def_index),
                },
            }],
            coverage: ParseCoverage {
                apk_parts: 1,
                dex_files: 1,
                parsed_classes: 1,
                parsed_methods: 0,
                parsed_fields: 0,
                warnings: Vec::new(),
            },
        }
    }
}
