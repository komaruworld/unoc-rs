use std::collections::BTreeMap;

use crate::cli::QueryConfig;
use crate::error::{Result, UnocRsError};
use crate::matcher::MatchStatus;
use crate::report::json::MappingReport;

pub fn run(config: QueryConfig) -> Result<()> {
    let file = std::fs::File::open(&config.mapping)?;
    let bundle: MappingReport = serde_json::from_reader(std::io::BufReader::new(file))?;
    let query = normalize_class_query(&config.class);
    let old_by_descriptor: BTreeMap<_, _> = bundle
        .old_app
        .classes
        .iter()
        .map(|class| (class.descriptor.as_str(), class.id))
        .collect();
    let new_by_descriptor: BTreeMap<_, _> = bundle
        .new_app
        .classes
        .iter()
        .map(|class| (class.descriptor.as_str(), class.id))
        .collect();

    let mut found = false;
    if let Some(old_id) = old_by_descriptor.get(query.as_str()) {
        for item in bundle
            .matches
            .classes
            .iter()
            .filter(|item| item.old_class_id == Some(*old_id))
        {
            print_class_match(&bundle, item, "old");
            found = true;
        }
    }
    if let Some(new_id) = new_by_descriptor.get(query.as_str()) {
        for item in bundle
            .matches
            .classes
            .iter()
            .filter(|item| item.new_class_id == Some(*new_id))
        {
            print_class_match(&bundle, item, "new");
            found = true;
        }
    }

    if found {
        Ok(())
    } else {
        Err(UnocRsError::Other(anyhow::anyhow!(
            "class not found in mapping: {}",
            config.class
        )))
    }
}

fn print_class_match(bundle: &MappingReport, item: &crate::matcher::ClassMatch, side: &str) {
    println!("side: {side}");
    println!("status: {:?}", item.status);
    println!("score: {:.2}", item.score);
    println!("old: {}", bundle.old_app.class_label(item.old_class_id));
    println!("new: {}", bundle.new_app.class_label(item.new_class_id));
    println!(
        "safe: {}",
        if item.status == MatchStatus::Matched
            && item
                .reasons
                .iter()
                .any(|reason| reason.starts_with("verified:"))
        {
            "true"
        } else {
            "false"
        }
    );
    if !item.reasons.is_empty() {
        println!("reasons:");
        for reason in &item.reasons {
            println!("  - {reason}");
        }
    }
    if !item.candidates.is_empty() {
        println!("candidates:");
        for candidate in item.candidates.iter().take(10) {
            println!(
                "  - {:.2} {}",
                candidate.score,
                bundle.new_app.class_label(Some(candidate.entity_id))
            );
            for reason in &candidate.reasons {
                println!("    reason: {reason}");
            }
        }
    }
}

fn normalize_class_query(value: &str) -> String {
    if value.starts_with('L') && value.ends_with(';') {
        value.to_string()
    } else {
        let slash = value.replace('.', "/");
        if slash.starts_with("L") {
            format!("{slash};")
        } else {
            format!("L{slash};")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_class_query;

    #[test]
    fn normalizes_descriptor_queries() {
        assert_eq!(normalize_class_query("LX/0hp4;"), "LX/0hp4;");
        assert_eq!(normalize_class_query("X/0hp4"), "LX/0hp4;");
        assert_eq!(
            normalize_class_query("com.example.Foo"),
            "Lcom/example/Foo;"
        );
    }
}
