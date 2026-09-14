pub mod html;
pub mod json;
pub mod proguard;
pub mod text;

use std::path::Path;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::matcher::MatchReport;
use crate::model::{AppModel, ClassModel};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportBundle {
    pub old_app: AppModel,
    pub new_app: AppModel,
    pub matches: MatchReport,
    pub min_confidence: f32,
    pub low_confidence: f32,
}

pub fn write_reports(
    bundle: &ReportBundle,
    output: &Path,
    write_html: bool,
    write_json: bool,
    write_proguard: bool,
    max_txt_rows_per_section: Option<usize>,
    txt_chunk_rows: Option<usize>,
) -> Result<()> {
    std::fs::create_dir_all(output)?;
    text::write_summary(bundle, &output.join("summary.txt"))?;
    text::write_mapping(
        bundle,
        &output.join("mapping.txt"),
        max_txt_rows_per_section,
    )?;
    text::write_tiered_mappings(bundle, output)?;
    text::write_mapping_chunks(bundle, output, max_txt_rows_per_section, txt_chunk_rows)?;
    text::write_member_mappings(bundle, output)?;
    if write_json {
        json::write_json(bundle, &output.join("mapping.json"))?;
    }
    if write_proguard {
        proguard::write_old_to_new(bundle, &output.join("old-to-new.pro"))?;
        proguard::write_new_to_old(bundle, &output.join("new-to-old.pro"))?;
    }
    if write_html {
        html::write_html(bundle, &output.join("report.html"))?;
    }
    Ok(())
}

pub fn class_label(app: &crate::model::AppModel, id: Option<usize>) -> String {
    let Some(id) = id else {
        return String::new();
    };
    let Some(class) = app.classes.iter().find(|class| class.id == id) else {
        return format!("#{id}");
    };
    let class_index = class
        .origin
        .class_def_index
        .map(|index| index.to_string())
        .unwrap_or_else(|| "?".to_string());
    format_class_label(class, &class_index)
}

pub struct ClassLabelIndex {
    labels: BTreeMap<usize, String>,
}

impl ClassLabelIndex {
    pub fn new(app: &AppModel) -> Self {
        let labels = app
            .classes
            .iter()
            .map(|class| {
                let class_index = class
                    .origin
                    .class_def_index
                    .map(|index| index.to_string())
                    .unwrap_or_else(|| "?".to_string());
                (class.id, format_class_label(class, &class_index))
            })
            .collect();
        Self { labels }
    }

    pub fn label(&self, id: Option<usize>) -> String {
        let Some(id) = id else {
            return String::new();
        };
        self.labels
            .get(&id)
            .cloned()
            .unwrap_or_else(|| format!("#{id}"))
    }
}

fn format_class_label(class: &ClassModel, class_index: &str) -> String {
    format!(
        "{} ({}!{}#{})",
        class.descriptor, class.origin.apk_part, class.origin.dex_file, class_index
    )
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use crate::matcher::MatchReport;
    use crate::model::{AppModel, ParseCoverage};

    use super::{write_reports, ReportBundle};

    #[test]
    fn writes_all_default_report_files() {
        let temp = tempdir().expect("temp dir");
        let bundle = ReportBundle {
            old_app: AppModel {
                apk_name: "old.apk".to_string(),
                package_name: None,
                classes: Vec::new(),
                coverage: ParseCoverage::default(),
            },
            new_app: AppModel {
                apk_name: "new.apk".to_string(),
                package_name: None,
                classes: Vec::new(),
                coverage: ParseCoverage::default(),
            },
            matches: MatchReport {
                classes: Vec::new(),
                methods: Vec::new(),
                fields: Vec::new(),
            },
            min_confidence: 0.80,
            low_confidence: 0.55,
        };
        write_reports(&bundle, temp.path(), true, true, true, None, Some(10_000)).expect("reports");
        assert!(temp.path().join("summary.txt").exists());
        assert!(temp.path().join("mapping.txt").exists());
        assert!(temp.path().join("verified.txt").exists());
        assert!(temp.path().join("name-only.txt").exists());
        assert!(temp.path().join("unsafe.txt").exists());
        assert!(temp.path().join("mapping.json").exists());
        assert!(temp.path().join("old-to-new.pro").exists());
        assert!(temp.path().join("new-to-old.pro").exists());
        assert!(temp.path().join("report.html").exists());
    }
}
