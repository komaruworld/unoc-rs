use rayon::ThreadPoolBuilder;

use crate::apk::{read_apk_part, read_apk_part_bytes};
use crate::cli::RunConfig;
use crate::dex::parse_dex;
use crate::error::{Result, UnocRsError};
use crate::fingerprint::fingerprint_app;
use crate::input::{resolve_app_input, ResolvedAppInput};
use crate::matcher::MatchStatus;
use crate::matcher::{match_app_models, match_apps, match_apps_low_memory, MatchConfig};
use crate::model::{
    build_app_model_streaming, AppModel, ClassModel, DexOrigin, ModelWarning, ParseCoverage,
};
use crate::report::{write_reports, ReportBundle};

pub fn run(config: RunConfig) -> Result<()> {
    let progress = crate::progress::Progress::new(config.progress);
    let mut progress = progress;
    progress.set_total(9);

    if !config.old_apk.exists() {
        return Err(UnocRsError::MissingInput(config.old_apk));
    }
    if !config.new_apk.exists() {
        return Err(UnocRsError::MissingInput(config.new_apk));
    }

    if let Some(threads) = config.threads {
        ThreadPoolBuilder::new()
            .num_threads(threads)
            .build_global()
            .map_err(|err| anyhow::anyhow!("failed to configure thread pool: {err}"))?;
    }

    let old_resolved = resolve_app_input(&config.old_apk)?;
    progress.stage_stats(
        "resolve input",
        format!("old parts={}", old_resolved.parts.len()),
    );

    let old_apk = read_resolved_input(old_resolved)?;
    let old_package = old_apk.package_name.clone();
    progress.stage_stats(
        "read apk",
        format!("old dex files={}", old_apk.dex_files.len()),
    );

    progress.stage_stats("build old model", model_build_mode(&config));
    let old_model = build_model_from_apk(old_apk, config.low_memory)?;
    crate::memory::trim_unused_memory();

    let new_resolved = resolve_app_input(&config.new_apk)?;
    progress.stage_stats(
        "resolve input",
        format!("new parts={}", new_resolved.parts.len()),
    );

    let new_apk = read_resolved_input(new_resolved)?;
    progress.stage_stats(
        "read apk",
        format!("new dex files={}", new_apk.dex_files.len()),
    );

    if config.strict_package {
        if let (Some(old_pkg), Some(new_pkg)) = (&old_package, &new_apk.package_name) {
            if old_pkg != new_pkg {
                return Err(UnocRsError::PackageMismatch {
                    old: old_pkg.clone(),
                    new: new_pkg.clone(),
                });
            }
        }
    }

    progress.stage_stats("build new model", model_build_mode(&config));
    let new_model = build_model_from_apk(new_apk, config.low_memory)?;
    crate::memory::trim_unused_memory();

    progress.stage_stats(
        "fingerprint",
        format!(
            "old classes={} new classes={}",
            old_model.classes.len(),
            new_model.classes.len()
        ),
    );
    let matches = {
        let old_fp = fingerprint_app(&old_model);
        let new_fp = fingerprint_app(&new_model);
        let max_candidates = if config.low_memory {
            config.max_candidates.min(3)
        } else {
            config.max_candidates
        };

        progress.stage_stats(
            "match",
            format!(
                "low-memory={}, members={}, verified-only={}, min={:.2}, low={:.2}",
                if config.low_memory { "yes" } else { "no" },
                if config.match_members { "yes" } else { "no" },
                if config.verified_only { "yes" } else { "no" },
                config.min_confidence,
                config.low_confidence,
            ),
        );
        let match_config = MatchConfig {
            min_confidence: config.min_confidence,
            low_confidence: config.low_confidence,
            max_candidates,
            verified_only: config.verified_only,
        };
        if config.low_memory {
            match_apps_low_memory(&old_fp, &new_fp, &match_config)
        } else if !config.match_members {
            match_apps(&old_fp, &new_fp, &match_config)
        } else {
            match_app_models(&old_model, &new_model, &old_fp, &new_fp, &match_config)
        }
    };
    crate::memory::trim_unused_memory();

    let match_stats = format_match_stats(&matches);

    let total_steps = old_model.coverage.parsed_classes + new_model.coverage.parsed_classes;
    let match_stage_stats = format!("{match_stats} | total classes={total_steps}");
    let bundle = ReportBundle {
        old_app: old_model,
        new_app: new_model,
        matches,
        min_confidence: config.min_confidence,
        low_confidence: config.low_confidence,
    };

    progress.stage_stats(
        "report",
        format!("{match_stage_stats} -> writing {}", config.output.display()),
    );

    write_reports(
        &bundle,
        &config.output,
        config.write_html,
        config.write_json,
        config.write_proguard,
        txt_row_limit(config.max_txt_rows),
        txt_chunk_rows(config.txt_chunk_rows),
    )
}

fn model_build_mode(config: &RunConfig) -> String {
    if config.low_memory {
        "low-memory mode: classes-only".to_string()
    } else {
        "full parser, streaming dex-by-dex".to_string()
    }
}

fn build_model_from_apk(input: crate::apk::ApkInput, low_memory: bool) -> Result<AppModel> {
    if low_memory {
        build_class_only_model(input)
    } else {
        build_app_model_streaming(input)
    }
}

fn format_match_stats(matches: &crate::matcher::MatchReport) -> String {
    let (matched, low, conflict, semantic_break, unresolved_old, unresolved_new) =
        matches.classes.iter().fold(
            (0usize, 0usize, 0usize, 0usize, 0usize, 0usize),
            |acc, item| {
                let mut acc = acc;
                match item.status {
                    MatchStatus::Matched => acc.0 += 1,
                    MatchStatus::LowConfidence => acc.1 += 1,
                    MatchStatus::Conflict => acc.2 += 1,
                    MatchStatus::SemanticBreak => acc.3 += 1,
                    MatchStatus::UnresolvedOld => acc.4 += 1,
                    MatchStatus::UnresolvedNew => acc.5 += 1,
                }
                acc
            },
        );

    format!(
        "classes matched={matched} low={low} conflict={conflict} semantic_break={semantic_break} unresolved_old={unresolved_old} unresolved_new={unresolved_new}",
    )
}

fn txt_row_limit(max_txt_rows: usize) -> Option<usize> {
    if max_txt_rows == 0 {
        None
    } else {
        Some(max_txt_rows)
    }
}

fn txt_chunk_rows(txt_chunk_rows: usize) -> Option<usize> {
    if txt_chunk_rows == 0 {
        None
    } else {
        Some(txt_chunk_rows)
    }
}

fn read_resolved_input(input: ResolvedAppInput) -> Result<crate::apk::ApkInput> {
    let mut merged = crate::apk::ApkInput {
        path: input.source_path.clone(),
        package_name: None,
        apk_parts: input.parts.len(),
        dex_files: Vec::new(),
    };
    for part in input.parts {
        let part_input = match read_apk_part_from_resolved(&input.source_path, part) {
            Ok(part_input) => part_input,
            Err(UnocRsError::NoDexFiles(_)) => continue,
            Err(error) => return Err(error),
        };
        if merged.package_name.is_none() {
            merged.package_name = part_input.package_name;
        }
        merged.dex_files.extend(part_input.dex_files);
    }
    if merged.dex_files.is_empty() {
        return Err(UnocRsError::NoDexFiles(input.source_path.clone()));
    }
    for (index, dex) in merged.dex_files.iter_mut().enumerate() {
        dex.dex_index = index;
    }
    Ok(merged)
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

fn build_class_only_model(input: crate::apk::ApkInput) -> Result<AppModel> {
    let crate::apk::ApkInput {
        path,
        package_name,
        apk_parts,
        dex_files,
    } = input;
    let mut classes = Vec::new();
    let mut warnings = Vec::new();
    let mut next_class_id = 0usize;
    let dex_count = dex_files.len();

    for (dex_index, dex) in dex_files.into_iter().enumerate() {
        let parsed = parse_dex(&dex.bytes)?;
        warnings.extend(parsed.raw.warnings.iter().map(|warning| ModelWarning {
            origin: format!("{}!{}:{}", dex.apk_part, dex.name, warning.origin),
            kind: format!("{:?}", warning.kind),
            message: warning.message.clone(),
        }));

        for (class_def_index, class_def) in parsed.raw.classes.iter().enumerate() {
            classes.push(ClassModel {
                id: next_class_id,
                descriptor: class_def.class_type.clone(),
                access_flags: class_def.access_flags,
                superclass: class_def.superclass.clone(),
                interfaces: class_def.interfaces.clone(),
                methods: Vec::new(),
                fields: Vec::new(),
                origin: DexOrigin {
                    apk_part: dex.apk_part.clone(),
                    dex_file: dex.name.clone(),
                    dex_index,
                    class_def_index: Some(class_def_index),
                },
            });
            next_class_id += 1;
        }
    }

    classes.sort_by(|left, right| left.descriptor.cmp(&right.descriptor));
    Ok(AppModel {
        apk_name: path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("apk")
            .to_string(),
        package_name,
        coverage: ParseCoverage {
            apk_parts,
            dex_files: dex_count,
            parsed_classes: classes.len(),
            parsed_methods: 0,
            parsed_fields: 0,
            warnings,
        },
        classes,
    })
}
