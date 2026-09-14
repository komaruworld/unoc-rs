use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use crate::dex::descriptor::descriptor_to_java_name;
use crate::error::Result;
use crate::matcher::{MatchStatus, SEMANTIC_BREAK_CLASS_KIND, UNSAFE_SAME_DESCRIPTOR_WEAK_SHAPE};
use crate::model::AppModel;
use crate::report::ReportBundle;

pub fn write_old_to_new(bundle: &ReportBundle, path: &Path) -> Result<()> {
    write_direction(bundle, path, &bundle.old_app, &bundle.new_app, true)
}

pub fn write_new_to_old(bundle: &ReportBundle, path: &Path) -> Result<()> {
    write_direction(bundle, path, &bundle.old_app, &bundle.new_app, false)
}

fn write_direction(
    bundle: &ReportBundle,
    path: &Path,
    old_app: &AppModel,
    new_app: &AppModel,
    old_to_new: bool,
) -> Result<()> {
    let file = std::fs::File::create(path)?;
    let mut out = std::io::BufWriter::new(file);
    let old_classes: BTreeMap<_, _> = old_app
        .classes
        .iter()
        .map(|class| (class.id, class))
        .collect();
    let new_classes: BTreeMap<_, _> = new_app
        .classes
        .iter()
        .map(|class| (class.id, class))
        .collect();
    for item in bundle.matches.classes.iter().filter(|item| {
        matches!(
            item.status,
            MatchStatus::Matched
                | MatchStatus::LowConfidence
                | MatchStatus::Conflict
                | MatchStatus::SemanticBreak
        )
    }) {
        let Some(old_id) = item.old_class_id else {
            continue;
        };
        let Some(new_id) = item.new_class_id else {
            continue;
        };
        let Some(old_class) = old_classes.get(&old_id) else {
            continue;
        };
        let Some(new_class) = new_classes.get(&new_id) else {
            continue;
        };
        let left = descriptor_to_java_name(if old_to_new {
            &old_class.descriptor
        } else {
            &new_class.descriptor
        });
        let right = descriptor_to_java_name(if old_to_new {
            &new_class.descriptor
        } else {
            &old_class.descriptor
        });
        if !is_safe(item) {
            writeln!(out, "# UNSAFE: {}", unsafe_reason(item))?;
        }
        writeln!(out, "{left} -> {right}:")?;
    }
    Ok(())
}

fn is_safe(item: &crate::matcher::ClassMatch) -> bool {
    item.status == MatchStatus::Matched
        && item
            .reasons
            .iter()
            .any(|reason| reason.starts_with("verified:"))
}

fn unsafe_reason(item: &crate::matcher::ClassMatch) -> String {
    if item.status == MatchStatus::SemanticBreak
        || item
            .reasons
            .iter()
            .any(|reason| reason == SEMANTIC_BREAK_CLASS_KIND)
    {
        return "semantic break".to_string();
    }
    if item
        .reasons
        .iter()
        .any(|reason| reason == UNSAFE_SAME_DESCRIPTOR_WEAK_SHAPE)
    {
        return "weak same-descriptor match".to_string();
    }
    format!("{:?}", item.status)
}
