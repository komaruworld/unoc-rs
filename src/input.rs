use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Result, UnocRsError};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum InputKind {
    ApkFile,
    BundleArchive,
    SplitDirectory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedAppInput {
    pub source_path: PathBuf,
    pub kind: InputKind,
    pub parts: Vec<ApkPart>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApkPart {
    pub part_name: String,
    pub path: Option<PathBuf>,
    #[serde(skip)]
    pub bytes: Vec<u8>,
}

pub fn resolve_app_input(path: &Path) -> Result<ResolvedAppInput> {
    if !path.exists() {
        return Err(UnocRsError::MissingInput(path.to_path_buf()));
    }
    if path.is_dir() {
        return resolve_split_directory(path);
    }
    match extension_lower(path).as_deref() {
        Some("apk") => resolve_single_apk(path),
        Some(ext) if is_bundle_extension(ext) => resolve_bundle_archive(path),
        _ => Err(UnocRsError::UnknownInputType(path.to_path_buf())),
    }
}

fn resolve_single_apk(path: &Path) -> Result<ResolvedAppInput> {
    let part_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("input.apk")
        .to_string();
    Ok(ResolvedAppInput {
        source_path: path.to_path_buf(),
        kind: InputKind::ApkFile,
        parts: vec![ApkPart {
            part_name,
            path: Some(path.to_path_buf()),
            bytes: Vec::new(),
        }],
    })
}

fn resolve_split_directory(path: &Path) -> Result<ResolvedAppInput> {
    let mut parts = Vec::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let apk_path = entry.path();
        match extension_lower(&apk_path).as_deref() {
            Some("apk") => {
                let part_name = apk_path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("split.apk")
                    .to_string();
                parts.push(ApkPart {
                    part_name,
                    path: Some(apk_path.clone()),
                    bytes: Vec::new(),
                });
            }
            Some(ext) if is_bundle_extension(ext) => {
                let archive_name = apk_path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("bundle")
                    .to_string();
                let bundle = resolve_bundle_archive(&apk_path)?;
                parts.extend(bundle.parts.into_iter().map(|mut part| {
                    part.part_name = format!("{}!{}", archive_name, part.part_name);
                    part
                }));
            }
            _ => continue,
        }
    }
    sort_parts(&mut parts);
    if parts.is_empty() {
        return Err(UnocRsError::NoApkParts(path.to_path_buf()));
    }
    Ok(ResolvedAppInput {
        source_path: path.to_path_buf(),
        kind: InputKind::SplitDirectory,
        parts,
    })
}

fn resolve_bundle_archive(path: &Path) -> Result<ResolvedAppInput> {
    let file = fs::File::open(path)?;
    let mut archive = zip::ZipArchive::new(file).map_err(|source| UnocRsError::InvalidApk {
        path: path.to_path_buf(),
        source,
    })?;
    let mut parts = Vec::new();
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|source| UnocRsError::InvalidApk {
                path: path.to_path_buf(),
                source,
            })?;
        if !entry.name().ends_with(".apk") {
            continue;
        }
        let part_name = Path::new(entry.name())
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("part.apk")
            .to_string();
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        parts.push(ApkPart {
            part_name,
            path: None,
            bytes,
        });
    }
    sort_parts(&mut parts);
    if parts.is_empty() {
        return Err(UnocRsError::NoApkParts(path.to_path_buf()));
    }
    Ok(ResolvedAppInput {
        source_path: path.to_path_buf(),
        kind: InputKind::BundleArchive,
        parts,
    })
}

fn sort_parts(parts: &mut [ApkPart]) {
    parts.sort_by(|left, right| {
        part_sort_key(&left.part_name).cmp(&part_sort_key(&right.part_name))
    });
}

fn part_sort_key(name: &str) -> (u8, String) {
    if name == "base.apk" || name.ends_with("!base.apk") {
        (0, name.to_string())
    } else {
        (1, name.to_string())
    }
}

fn extension_lower(path: &Path) -> Option<String> {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase())
}

fn is_bundle_extension(ext: &str) -> bool {
    matches!(ext, "apks" | "xapk" | "apkm")
}
