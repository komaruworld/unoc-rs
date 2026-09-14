pub mod manifest;

use std::fs::File;
use std::io::{Read, Seek};
use std::path::{Path, PathBuf};

use crate::error::{Result, UnocRsError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApkInput {
    pub path: PathBuf,
    pub package_name: Option<String>,
    pub apk_parts: usize,
    pub dex_files: Vec<DexBlob>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexBlob {
    pub apk_part: String,
    pub name: String,
    pub dex_index: usize,
    pub bytes: Vec<u8>,
}

pub fn read_apk(path: &Path) -> Result<ApkInput> {
    let part_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("input.apk");
    read_apk_part(path, part_name)
}

pub fn read_apk_part(path: &Path, part_name: &str) -> Result<ApkInput> {
    let file = File::open(path)?;
    read_apk_archive(path, part_name, file)
}

pub fn read_apk_part_bytes(
    source_path: &Path,
    part_name: &str,
    bytes: Vec<u8>,
) -> Result<ApkInput> {
    let cursor = std::io::Cursor::new(bytes);
    read_apk_archive(source_path, part_name, cursor)
}

fn read_apk_archive<R: Read + Seek>(path: &Path, part_name: &str, reader: R) -> Result<ApkInput> {
    let mut archive = zip::ZipArchive::new(reader).map_err(|source| UnocRsError::InvalidApk {
        path: path.to_path_buf(),
        source,
    })?;

    let mut dex_files = Vec::new();
    let mut manifest_bytes = None;

    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|source| UnocRsError::InvalidApk {
                path: path.to_path_buf(),
                source,
            })?;
        let name = entry.name().to_string();

        if name == "AndroidManifest.xml" {
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            manifest_bytes = Some(bytes);
            continue;
        }

        if is_classes_dex_name(&name) {
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            dex_files.push(DexBlob {
                apk_part: part_name.to_string(),
                name,
                dex_index: 0,
                bytes,
            });
        }
    }

    dex_files.sort_by_key(|dex| dex_sort_key(&dex.name));
    for (index, dex) in dex_files.iter_mut().enumerate() {
        dex.dex_index = index;
    }

    if dex_files.is_empty() {
        return Err(UnocRsError::NoDexFiles(path.to_path_buf()));
    }

    let package_name = manifest_bytes
        .as_deref()
        .and_then(manifest::read_package_name);

    Ok(ApkInput {
        path: path.to_path_buf(),
        package_name,
        apk_parts: 1,
        dex_files,
    })
}

fn is_classes_dex_name(name: &str) -> bool {
    if name == "classes.dex" {
        return true;
    }
    if !name.starts_with("classes") || !name.ends_with(".dex") {
        return false;
    }
    let middle = &name["classes".len()..name.len() - ".dex".len()];
    !middle.is_empty() && middle.chars().all(|ch| ch.is_ascii_digit())
}

fn dex_sort_key(name: &str) -> usize {
    if name == "classes.dex" {
        return 1;
    }
    let middle = &name["classes".len()..name.len() - ".dex".len()];
    middle.parse::<usize>().unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::{dex_sort_key, is_classes_dex_name};

    #[test]
    fn identifies_classes_dex_entries() {
        assert!(is_classes_dex_name("classes.dex"));
        assert!(is_classes_dex_name("classes2.dex"));
        assert!(is_classes_dex_name("classes10.dex"));
        assert!(!is_classes_dex_name("classes.dex.bak"));
        assert!(!is_classes_dex_name("assets/classes.dex"));
    }

    #[test]
    fn sorts_primary_dex_first() {
        assert_eq!(dex_sort_key("classes.dex"), 1);
        assert_eq!(dex_sort_key("classes2.dex"), 2);
        assert_eq!(dex_sort_key("classes10.dex"), 10);
    }
}
