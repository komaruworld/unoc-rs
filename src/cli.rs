use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::error::{Result, UnocRsError};
use crate::memory::{parse_memory_limit, MemoryLimit, DEFAULT_MEMORY_LIMIT};

#[derive(Debug, Clone, Parser)]
#[command(name = "unoc-rs")]
#[command(about = "Map classes, methods, and fields between two APK versions")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<CliCommand>,

    #[arg(value_name = "OLD_APK")]
    pub old_apk: Option<PathBuf>,

    #[arg(value_name = "NEW_APK")]
    pub new_apk: Option<PathBuf>,

    #[arg(short = 'o', long = "output", value_name = "DIR")]
    pub output: Option<PathBuf>,

    #[arg(long = "threads")]
    pub threads: Option<usize>,

    #[arg(
        long = "memory-limit",
        global = true,
        default_value = DEFAULT_MEMORY_LIMIT,
        value_parser = parse_memory_limit,
        help = "Max address space, e.g. 12g or 2048m; 0 disables (required on Windows)"
    )]
    pub memory_limit: MemoryLimit,

    #[arg(long = "min-confidence", default_value_t = 0.80)]
    pub min_confidence: f32,

    #[arg(long = "low-confidence", default_value_t = 0.55)]
    pub low_confidence: f32,

    #[arg(long = "max-candidates", default_value_t = 10)]
    pub max_candidates: usize,

    #[arg(long = "max-txt-rows", default_value_t = 2000)]
    pub max_txt_rows: usize,

    #[arg(long = "txt-chunk-rows", default_value_t = 10000)]
    pub txt_chunk_rows: usize,

    #[arg(
        long = "full-txt",
        default_value_t = false,
        help = "Write one complete mapping.txt and disable split mapping-parts"
    )]
    pub full_txt: bool,

    #[arg(long = "low-memory", default_value_t = false)]
    pub low_memory: bool,

    #[arg(
        long = "members",
        default_value_t = false,
        help = "Also match methods/fields and write methods.tsv/fields.tsv"
    )]
    pub members: bool,

    #[arg(
        long = "verified-only",
        default_value_t = false,
        help = "Mark classes as matched only when strict class fingerprint/pattern checks verify"
    )]
    pub verified_only: bool,

    #[arg(long = "html", default_value_t = true, action = clap::ArgAction::SetTrue)]
    pub html: bool,

    #[arg(long = "no-html", default_value_t = false)]
    pub no_html: bool,

    #[arg(long = "json", default_value_t = true, action = clap::ArgAction::SetTrue)]
    pub json: bool,

    #[arg(long = "no-json", default_value_t = false)]
    pub no_json: bool,

    #[arg(long = "proguard", default_value_t = true, action = clap::ArgAction::SetTrue)]
    pub proguard: bool,

    #[arg(long = "no-proguard", default_value_t = false)]
    pub no_proguard: bool,

    #[arg(long = "strict-package", default_value_t = true, action = clap::ArgAction::SetTrue)]
    pub strict_package: bool,

    #[arg(long = "no-strict-package", default_value_t = false)]
    pub no_strict_package: bool,

    #[arg(
        long = "progress",
        global = true,
        default_value_t = true,
        action = clap::ArgAction::SetTrue,
        help = "Show progress bar and stage stats (enabled by default)"
    )]
    pub progress: bool,

    #[arg(
        long = "no-progress",
        global = true,
        default_value_t = false,
        help = "Disable progress bar and stage stats"
    )]
    pub no_progress: bool,
}

#[derive(Debug, Clone, Subcommand)]
pub enum CliCommand {
    #[command(about = "Inspect APK, bundle, or split directory coverage")]
    Inspect(InspectArgs),
    #[command(about = "Audit DEX references against an APK or split bundle")]
    AuditRefs(AuditRefsArgs),
    #[command(about = "Query one class in a generated mapping.json report")]
    Query(QueryArgs),
    #[command(about = "Apply class descriptor remapping to smali/java source trees")]
    Remap(RemapArgs),
}

#[derive(Debug, Clone, Args)]
pub struct InspectArgs {
    #[arg(value_name = "INPUT")]
    pub input: PathBuf,

    #[arg(short = 'o', long = "output", value_name = "DIR")]
    pub output: PathBuf,
}

#[derive(Debug, Clone, Args)]
pub struct AuditRefsArgs {
    #[arg(value_name = "TARGET")]
    pub target: PathBuf,

    #[arg(
        long = "source-dex",
        value_name = "ENTRY",
        help = "DEX entry to audit, such as classes37.dex or base.apk!classes37.dex"
    )]
    pub source_dexes: Vec<String>,

    #[arg(
        long = "references",
        value_name = "DEX",
        help = "Standalone DEX whose references should be audited"
    )]
    pub references: Vec<PathBuf>,

    #[arg(
        long = "ignore-prefix",
        value_name = "DESCRIPTOR",
        help = "Additional descriptor prefix to exclude"
    )]
    pub ignore_prefixes: Vec<String>,

    #[arg(
        long = "include-prefix",
        value_name = "DESCRIPTOR",
        help = "Descriptor prefix to include even when ignored by default"
    )]
    pub include_prefixes: Vec<String>,

    #[arg(
        long = "mapping",
        value_name = "FILE",
        help = "Optional mapping.json, ProGuard, or mapping.txt candidate source"
    )]
    pub mapping: Option<PathBuf>,

    #[arg(
        long = "allow-missing",
        value_name = "N",
        default_value_t = 0,
        help = "Allow up to N unresolved reference sites"
    )]
    pub allow_missing: usize,

    #[arg(short = 'o', long = "output", value_name = "DIR")]
    pub output: PathBuf,
}

#[derive(Debug, Clone, Args)]
pub struct QueryArgs {
    #[arg(short = 'm', long = "mapping", value_name = "JSON")]
    pub mapping: PathBuf,

    #[arg(value_name = "CLASS")]
    pub class: String,
}

#[derive(Debug, Clone, Args)]
pub struct RemapArgs {
    #[arg(short = 'm', long = "mapping", value_name = "FILE")]
    pub mapping: PathBuf,

    #[arg(value_name = "INPUT")]
    pub input: PathBuf,

    #[arg(short = 'o', long = "output", value_name = "DIR")]
    pub output: PathBuf,

    #[arg(
        long = "include-unsafe",
        default_value_t = false,
        help = "Also apply mappings marked Conflict/SemanticBreak/LowConfidence"
    )]
    pub include_unsafe: bool,
}

#[derive(Debug, Clone)]
pub enum AppCommand {
    Compare(RunConfig),
    Inspect(InspectConfig),
    AuditRefs(AuditRefsConfig),
    Query(QueryConfig),
    Remap(RemapConfig),
}

#[derive(Debug, Clone)]
pub struct RunConfig {
    pub old_apk: PathBuf,
    pub new_apk: PathBuf,
    pub output: PathBuf,
    pub threads: Option<usize>,
    pub min_confidence: f32,
    pub low_confidence: f32,
    pub max_candidates: usize,
    pub max_txt_rows: usize,
    pub txt_chunk_rows: usize,
    pub low_memory: bool,
    pub write_html: bool,
    pub write_json: bool,
    pub write_proguard: bool,
    pub strict_package: bool,
    pub progress: bool,
    pub match_members: bool,
    pub verified_only: bool,
}

#[derive(Debug, Clone)]
pub struct InspectConfig {
    pub input: PathBuf,
    pub output: PathBuf,
    pub progress: bool,
}

#[derive(Debug, Clone)]
pub struct AuditRefsConfig {
    pub target: PathBuf,
    pub source_dexes: Vec<String>,
    pub references: Vec<PathBuf>,
    pub ignore_prefixes: Vec<String>,
    pub include_prefixes: Vec<String>,
    pub mapping: Option<PathBuf>,
    pub allow_missing: usize,
    pub output: PathBuf,
    pub progress: bool,
}

#[derive(Debug, Clone)]
pub struct QueryConfig {
    pub mapping: PathBuf,
    pub class: String,
}

#[derive(Debug, Clone)]
pub struct RemapConfig {
    pub mapping: PathBuf,
    pub input: PathBuf,
    pub output: PathBuf,
    pub include_unsafe: bool,
}

impl Cli {
    pub fn into_command(self) -> Result<AppCommand> {
        let progress = self.progress && !self.no_progress;
        match self.command {
            Some(CliCommand::Inspect(args)) => Ok(AppCommand::Inspect(InspectConfig {
                input: args.input,
                output: args.output,
                progress,
            })),
            Some(CliCommand::AuditRefs(args)) => Ok(AppCommand::AuditRefs(AuditRefsConfig {
                target: args.target,
                source_dexes: args.source_dexes,
                references: args.references,
                ignore_prefixes: args.ignore_prefixes,
                include_prefixes: args.include_prefixes,
                mapping: args.mapping,
                allow_missing: args.allow_missing,
                output: args.output,
                progress,
            })),
            Some(CliCommand::Query(args)) => Ok(AppCommand::Query(QueryConfig {
                mapping: args.mapping,
                class: args.class,
            })),
            Some(CliCommand::Remap(args)) => Ok(AppCommand::Remap(RemapConfig {
                mapping: args.mapping,
                input: args.input,
                output: args.output,
                include_unsafe: args.include_unsafe,
            })),
            None => self.into_compare_config().map(AppCommand::Compare),
        }
        .map(|mut command| {
            if let AppCommand::Compare(config) = &mut command {
                config.progress = progress;
            }
            command
        })
    }

    fn into_compare_config(self) -> Result<RunConfig> {
        validate_confidence(self.min_confidence)?;
        validate_confidence(self.low_confidence)?;
        if self.min_confidence < self.low_confidence {
            return Err(UnocRsError::InvalidThresholdOrder);
        }

        let write_html = !self.no_html && self.html;
        let write_json = !self.no_json && self.json;
        let write_proguard = !self.no_proguard && self.proguard;

        let max_txt_rows = if self.full_txt { 0 } else { self.max_txt_rows };
        let txt_chunk_rows = if self.full_txt {
            0
        } else {
            self.txt_chunk_rows
        };

        Ok(RunConfig {
            old_apk: self.old_apk.ok_or(UnocRsError::MissingCompareInput)?,
            new_apk: self.new_apk.ok_or(UnocRsError::MissingCompareInput)?,
            output: self.output.ok_or(UnocRsError::MissingOutput)?,
            threads: self.threads,
            min_confidence: self.min_confidence,
            low_confidence: self.low_confidence,
            max_candidates: self.max_candidates,
            max_txt_rows,
            txt_chunk_rows,
            low_memory: self.low_memory,
            write_html,
            write_json,
            write_proguard,
            strict_package: !self.no_strict_package && self.strict_package,
            progress: self.progress && !self.no_progress,
            match_members: self.members,
            verified_only: self.verified_only,
        })
    }
}

fn validate_confidence(value: f32) -> Result<()> {
    if (0.0..=1.0).contains(&value) {
        Ok(())
    } else {
        Err(UnocRsError::InvalidThreshold { value })
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use clap::Parser;

    use super::{AppCommand, Cli};

    #[test]
    fn default_reports_do_not_force_member_matching() {
        let cli = Cli::try_parse_from(["unoc-rs", "old.apk", "new.apk", "--output", "report"])
            .expect("default CLI");
        let AppCommand::Compare(config) = cli.into_command().expect("compare config") else {
            panic!("expected compare command");
        };

        assert!(config.write_html);
        assert!(config.write_json);
        assert!(!config.match_members);
    }

    #[test]
    fn members_flag_enables_member_matching() {
        let cli = Cli::try_parse_from([
            "unoc-rs",
            "old.apk",
            "new.apk",
            "--output",
            "report",
            "--members",
        ])
        .expect("members CLI");
        let AppCommand::Compare(config) = cli.into_command().expect("compare config") else {
            panic!("expected compare command");
        };

        assert!(config.match_members);
    }

    #[test]
    fn audit_refs_accepts_repeatable_sources_and_prefixes() {
        let cli = Cli::try_parse_from([
            "unoc-rs",
            "audit-refs",
            "patched.xapk",
            "--source-dex",
            "classes37.dex",
            "--references",
            "bridge.dex",
            "--ignore-prefix",
            "Ldev/fotok/",
            "--include-prefix",
            "Ljava/",
            "--allow-missing",
            "2",
            "--output",
            "report",
        ])
        .expect("audit CLI");
        let AppCommand::AuditRefs(config) = cli.into_command().expect("audit config") else {
            panic!("expected audit command");
        };

        assert_eq!(config.source_dexes, ["classes37.dex"]);
        assert_eq!(config.references, [PathBuf::from("bridge.dex")]);
        assert_eq!(config.ignore_prefixes, ["Ldev/fotok/"]);
        assert_eq!(config.include_prefixes, ["Ljava/"]);
        assert_eq!(config.allow_missing, 2);
    }
}
