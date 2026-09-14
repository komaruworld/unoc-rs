use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use crate::cli::RemapConfig;
use crate::dex::descriptor::descriptor_to_java_name;
use crate::error::{Result, UnocRsError};
use crate::matcher::MatchStatus;
use crate::report::json::MappingReport;

#[derive(Debug, Clone)]
struct Replacement {
    old: String,
    new: String,
}

pub fn run(config: RemapConfig) -> Result<()> {
    if !config.input.exists() {
        return Err(UnocRsError::MissingInput(config.input));
    }
    validate_output_path(&config.input, &config.output)?;
    let replacements = load_replacements(&config.mapping, config.include_unsafe)?;
    if replacements.is_empty() {
        return Err(UnocRsError::Other(anyhow::anyhow!(
            "no usable mappings found in {}",
            config.mapping.display()
        )));
    }

    let index = ReplacementIndex::new(&replacements);
    if config.input.is_file() {
        if let Some(parent) = config.output.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        rewrite_file(&config.input, &config.output, &index)?;
    } else {
        rewrite_dir(&config.input, &config.output, &index)?;
    }
    Ok(())
}

fn load_replacements(path: &Path, include_unsafe: bool) -> Result<Vec<Replacement>> {
    if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
        return load_json_replacements(path, include_unsafe);
    }

    let text = std::fs::read_to_string(path)?;
    let mut replacements = Vec::new();
    let mut skip_next_unsafe_mapping = false;
    for line in text.lines() {
        if line.trim_start().starts_with("# UNSAFE") {
            skip_next_unsafe_mapping = !include_unsafe;
            continue;
        }
        if skip_next_unsafe_mapping {
            if parse_descriptor_mapping_line(line).is_some()
                || parse_proguard_mapping_line(line).is_some()
            {
                skip_next_unsafe_mapping = false;
            }
            continue;
        }
        if let Some((old, new)) = parse_descriptor_mapping_line(line) {
            replacements.push(Replacement { old, new });
        } else if let Some((old, new)) = parse_proguard_mapping_line(line) {
            replacements.push(Replacement {
                old: java_name_to_descriptor(&old),
                new: java_name_to_descriptor(&new),
            });
        }
    }
    Ok(normalize_replacements(replacements))
}

pub(crate) fn load_safe_descriptor_mappings(path: &Path) -> Result<BTreeMap<String, String>> {
    Ok(load_replacements(path, false)?
        .into_iter()
        .map(|replacement| (replacement.old, replacement.new))
        .collect())
}

fn load_json_replacements(path: &Path, include_unsafe: bool) -> Result<Vec<Replacement>> {
    let file = std::fs::File::open(path)?;
    let bundle: MappingReport = serde_json::from_reader(std::io::BufReader::new(file))?;
    let old_classes: BTreeMap<_, _> = bundle
        .old_app
        .classes
        .iter()
        .map(|class| (class.id, class.descriptor.as_str()))
        .collect();
    let new_classes: BTreeMap<_, _> = bundle
        .new_app
        .classes
        .iter()
        .map(|class| (class.id, class.descriptor.as_str()))
        .collect();
    let replacements = bundle
        .matches
        .classes
        .iter()
        .filter(|item| {
            item.status == MatchStatus::Matched
                || (include_unsafe
                    && matches!(
                        item.status,
                        MatchStatus::LowConfidence
                            | MatchStatus::Conflict
                            | MatchStatus::SemanticBreak
                    ))
        })
        .filter_map(|item| {
            let old = old_classes.get(&item.old_class_id?)?;
            let new = new_classes.get(&item.new_class_id?)?;
            Some(Replacement {
                old: (*old).to_string(),
                new: (*new).to_string(),
            })
        })
        .collect();
    Ok(normalize_replacements(replacements))
}

fn normalize_replacements(mut replacements: Vec<Replacement>) -> Vec<Replacement> {
    replacements.retain(|item| item.old != item.new);
    replacements.sort_by(|left, right| {
        right
            .old
            .len()
            .cmp(&left.old.len())
            .then(left.old.cmp(&right.old))
    });
    replacements.dedup_by(|left, right| left.old == right.old && left.new == right.new);
    replacements
}

fn validate_output_path(input: &Path, output: &Path) -> Result<()> {
    let source = input.canonicalize()?;
    let mut destination = PathBuf::new();
    // Resolve existing symlinks before interpreting '..', including when the
    // final output directory does not exist yet.
    for component in std::path::absolute(output)?.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                destination.pop();
            }
            Component::Prefix(_) | Component::RootDir => destination.push(component.as_os_str()),
            Component::Normal(_) => {
                destination.push(component.as_os_str());
                match destination.canonicalize() {
                    Ok(path) => destination = path,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
    }
    if destination.exists() {
        destination = destination.canonicalize()?;
    }
    if source == destination
        || (source.is_dir()
            && (destination.starts_with(&source) || source.starts_with(&destination)))
    {
        return Err(UnocRsError::Other(anyhow::anyhow!(
            "remap input and output must not overlap: {} and {}",
            input.display(),
            output.display()
        )));
    }
    Ok(())
}

fn reject_symlink(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(UnocRsError::Other(
            anyhow::anyhow!("remap does not follow symbolic links: {}", path.display()),
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn rewrite_dir(input: &Path, output: &Path, index: &ReplacementIndex<'_>) -> Result<()> {
    reject_symlink(input)?;
    reject_symlink(output)?;
    std::fs::create_dir_all(output)?;
    for entry in std::fs::read_dir(input)? {
        let entry = entry?;
        let source = entry.path();
        let target = output.join(entry.file_name());
        reject_symlink(&source)?;
        if source.is_dir() {
            rewrite_dir(&source, &target, index)?;
        } else if source.is_file() {
            rewrite_file(&source, &target, index)?;
        }
    }
    Ok(())
}

fn rewrite_file(input: &Path, output: &Path, index: &ReplacementIndex<'_>) -> Result<()> {
    reject_symlink(input)?;
    reject_symlink(output)?;
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if !is_text_like(input) {
        std::fs::copy(input, output)?;
        return Ok(());
    }

    let mut bytes = Vec::new();
    std::fs::File::open(input)?.read_to_end(&mut bytes)?;
    let Ok(text) = String::from_utf8(bytes) else {
        std::fs::copy(input, output)?;
        return Ok(());
    };

    std::fs::write(output, index.rewrite(&text))?;
    Ok(())
}

struct ReplacementIndex<'a> {
    descriptors: BTreeMap<&'a str, &'a str>,
    names: BTreeMap<String, String>,
}

impl<'a> ReplacementIndex<'a> {
    fn new(replacements: &'a [Replacement]) -> Self {
        let mut descriptors = BTreeMap::new();
        let mut names = BTreeMap::new();
        for replacement in replacements {
            descriptors.insert(replacement.old.as_str(), replacement.new.as_str());
            names.insert(
                descriptor_to_smali_path(&replacement.old),
                descriptor_to_smali_path(&replacement.new),
            );
            names.insert(
                descriptor_to_java_name(&replacement.old),
                descriptor_to_java_name(&replacement.new),
            );
        }
        Self { descriptors, names }
    }

    fn rewrite(&self, text: &str) -> String {
        let mut output = String::with_capacity(text.len());
        let mut cursor = 0;
        while cursor < text.len() {
            let tail = &text[cursor..];
            let end = tail.find(|ch| !is_name_char(ch)).unwrap_or(tail.len());
            if end == 0 {
                let ch = tail.chars().next().unwrap_or_default();
                output.push(ch);
                cursor += ch.len_utf8();
                continue;
            }
            let name = &tail[..end];
            if tail.as_bytes().get(end) == Some(&b';') {
                // Primitive parameters may directly precede an object type:
                // (ILa/A;La/B;)V. Arrays are delimited by '[' already.
                let prefix = name
                    .bytes()
                    .take_while(|byte| {
                        matches!(byte, b'B' | b'C' | b'D' | b'F' | b'I' | b'J' | b'S' | b'Z')
                    })
                    .count();
                if let Some(replacement) = self.descriptors.get(&tail[prefix..=end]) {
                    output.push_str(&name[..prefix]);
                    output.push_str(replacement);
                    cursor += end + 1;
                    continue;
                }
            }

            if let Some(replacement) = self.names.get(name) {
                output.push_str(replacement);
            } else if let Some((prefix, replacement)) = name
                .rmatch_indices('.')
                .find_map(|(prefix, _)| self.names.get(&name[..prefix]).map(|new| (prefix, new)))
            {
                // Preserve Java member access after a complete class name.
                output.push_str(replacement);
                output.push_str(&name[prefix..]);
            } else {
                output.push_str(name);
            }
            cursor += end;
        }
        output
    }
}

fn is_name_char(ch: char) -> bool {
    // Combining marks and other Unicode identifier characters must not split
    // an unmapped name into a prefix that happens to have a mapping.
    ch.is_ascii_alphanumeric()
        || matches!(ch, '_' | '$' | '/' | '.')
        || (!ch.is_ascii() && !ch.is_whitespace())
}

fn is_text_like(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|ext| ext.to_str()),
        Some("smali" | "java" | "kt" | "xml" | "txt" | "pro" | "cfg" | "properties")
    )
}

fn parse_descriptor_mapping_line(line: &str) -> Option<(String, String)> {
    let (left, right) = line.split_once(" -> ")?;
    let old = last_descriptor_token(left)?;
    let new = first_descriptor_token(right)?;
    Some((old, new))
}

fn parse_proguard_mapping_line(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    if line.starts_with('#') || !line.ends_with(':') {
        return None;
    }
    let (old, new) = line.trim_end_matches(':').split_once(" -> ")?;
    if old.contains(' ') || new.contains(' ') {
        return None;
    }
    Some((old.to_string(), new.to_string()))
}

fn last_descriptor_token(value: &str) -> Option<String> {
    descriptor_tokens(value).pop()
}

fn first_descriptor_token(value: &str) -> Option<String> {
    descriptor_tokens(value).into_iter().next()
}

fn descriptor_tokens(value: &str) -> Vec<String> {
    let bytes = value.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'L' {
            if let Some(end) = value[index..].find(';') {
                tokens.push(value[index..=index + end].to_string());
                index += end + 1;
                continue;
            }
        }
        index += 1;
    }
    tokens
}

fn java_name_to_descriptor(value: &str) -> String {
    format!("L{};", value.replace('.', "/"))
}

fn descriptor_to_smali_path(value: &str) -> String {
    value
        .strip_prefix('L')
        .and_then(|item| item.strip_suffix(';'))
        .unwrap_or(value)
        .to_string()
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::{load_replacements, parse_descriptor_mapping_line};

    #[test]
    fn loads_compact_json_class_mapping() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("mapping.json");
        std::fs::write(
            &path,
            r#"{
                "schema_version": 1,
                "old_app": {
                    "apk_name": "old.apk",
                    "package_name": null,
                    "classes": [{
                        "id": 1,
                        "descriptor": "La/Old;",
                        "origin": {
                            "apk_part": "base.apk",
                            "dex_file": "classes.dex",
                            "dex_index": 0,
                            "class_def_index": 1
                        }
                    }],
                    "coverage": {}
                },
                "new_app": {
                    "apk_name": "new.apk",
                    "package_name": null,
                    "classes": [{
                        "id": 2,
                        "descriptor": "Lb/New;",
                        "origin": {
                            "apk_part": "base.apk",
                            "dex_file": "classes2.dex",
                            "dex_index": 1,
                            "class_def_index": 2
                        }
                    }],
                    "coverage": {}
                },
                "matches": {
                    "classes": [{
                        "old_class_id": 1,
                        "new_class_id": 2,
                        "score": 1.0,
                        "status": "Matched",
                        "reasons": ["verified: fixture"],
                        "candidates": []
                    }],
                    "method_count": 0,
                    "field_count": 0
                },
                "min_confidence": 0.8,
                "low_confidence": 0.55
            }"#,
        )
        .expect("compact JSON");

        let replacements = load_replacements(&path, false).expect("JSON replacements");

        assert_eq!(replacements.len(), 1);
        assert_eq!(replacements[0].old, "La/Old;");
        assert_eq!(replacements[0].new, "Lb/New;");
    }

    #[test]
    fn parses_human_mapping_descriptor_line() {
        let line = "[0.96] La/Old; (base.apk!classes.dex#1) -> Lb/New; (base.apk!classes.dex#2)";
        let parsed = parse_descriptor_mapping_line(line).expect("mapping");
        assert_eq!(parsed.0, "La/Old;");
        assert_eq!(parsed.1, "Lb/New;");
    }

    #[test]
    fn skips_unsafe_proguard_mapping_by_default() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("old-to-new.pro");
        std::fs::write(
            &path,
            "a.Safe -> b.Safe:\n# UNSAFE: semantic break\na.Bad -> b.Bad:\n",
        )
        .expect("write");

        let safe = load_replacements(&path, false).expect("safe replacements");
        assert_eq!(safe.len(), 1);
        assert_eq!(safe[0].old, "La/Safe;");

        let unsafe_included = load_replacements(&path, true).expect("all replacements");
        assert_eq!(unsafe_included.len(), 2);
    }
}
