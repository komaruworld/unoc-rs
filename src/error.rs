use std::path::PathBuf;

pub type Result<T> = std::result::Result<T, UnocRsError>;

#[derive(Debug, thiserror::Error)]
pub enum UnocRsError {
    #[error("input APK path does not exist: {0}")]
    MissingInput(PathBuf),

    #[error("compare mode requires OLD_APK and NEW_APK")]
    MissingCompareInput,

    #[error("compare mode requires -o/--output")]
    MissingOutput,

    #[error("min-confidence must be greater than or equal to low-confidence")]
    InvalidThresholdOrder,

    #[error("confidence threshold must be between 0.0 and 1.0: {value}")]
    InvalidThreshold { value: f32 },

    #[error("memory limit is too large for this platform: {limit}")]
    MemoryLimitTooLarge { limit: String },

    #[error("process memory limits are not supported on this platform; use --memory-limit 0")]
    MemoryLimitUnsupported,

    #[error("memory limit {limit} is above the process hard limit {hard_limit}")]
    MemoryLimitAboveHardLimit { limit: String, hard_limit: String },

    #[error("failed to set memory limit to {limit}: {source}")]
    MemoryLimitFailed {
        limit: String,
        #[source]
        source: std::io::Error,
    },

    #[error("file is not a readable APK/ZIP: {path}")]
    InvalidApk {
        path: PathBuf,
        #[source]
        source: zip::result::ZipError,
    },

    #[error("no DEX files found in {0}")]
    NoDexFiles(PathBuf),

    #[error("input type cannot be recognized: {0}")]
    UnknownInputType(PathBuf),

    #[error("no APK parts found in input: {0}")]
    NoApkParts(PathBuf),

    #[error("audit-refs requires at least one --source-dex or --references input")]
    MissingAuditSources,

    #[error("audit source DEX selector(s) did not match the target bundle: {selectors}")]
    AuditSourceDexNotFound { selectors: String },

    #[error("cannot audit {origin}: incomplete DEX parsing: {reason}")]
    IncompleteAuditSource { origin: String, reason: String },

    #[error("invalid empty {option} value: {prefix:?}")]
    InvalidAuditPrefix { option: String, prefix: String },

    #[error(
        "reference audit found {unresolved} unresolved site(s), allowed {allowed}; reports: {output}"
    )]
    ReferenceAuditFailed {
        unresolved: usize,
        allowed: usize,
        output: PathBuf,
    },

    #[error(
        "unexpected end of DEX at offset {offset}; needed {needed} bytes, file length is {len}"
    )]
    UnexpectedEof {
        offset: usize,
        needed: usize,
        len: usize,
    },

    #[error("invalid DEX magic")]
    InvalidDexMagic,

    #[error("unsupported DEX version: {0}")]
    UnsupportedDexVersion(String),

    #[error("invalid DEX header: {reason}")]
    InvalidDexHeader { reason: String },

    #[error("invalid LEB128 value at offset {offset}")]
    InvalidLeb128 { offset: usize },

    #[error("invalid encoded class data: {reason}")]
    InvalidClassData { reason: String },

    #[error("invalid instruction at code-unit offset {offset_code_unit}, opcode 0x{opcode:02x}")]
    InvalidInstruction { offset_code_unit: usize, opcode: u8 },

    #[error("package names differ: {old} vs {new}\nhint: use --no-strict-package if these APKs are still related")]
    PackageMismatch { old: String, new: String },

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
