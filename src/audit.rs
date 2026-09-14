use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::apk::{read_apk_part, read_apk_part_bytes, ApkInput};
use crate::cli::AuditRefsConfig;
use crate::dex::instructions::InstructionReference;
use crate::dex::raw::{ClassDef, FieldId, MethodId, RawDex};
use crate::error::{Result, UnocRsError};
use crate::input::{resolve_app_input, ApkPart};

const ACC_STATIC: u32 = 0x0008;
const DEFAULT_IGNORED_PREFIXES: &[&str] = &[
    "Landroid/",
    "Landroidx/",
    "Lcom/android/",
    "Ldalvik/",
    "Lj$/",
    "Ljava/",
    "Ljavax/",
    "Lkotlin/",
    "Lkotlinx/",
    "Llibcore/",
    "Lorg/apache/http/",
    "Lorg/json/",
    "Lorg/w3c/dom/",
    "Lorg/xml/sax/",
    "Lorg/xmlpull/",
    "Lsun/",
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct DexLocation {
    apk_part: String,
    dex_file: String,
    standalone: bool,
}

impl DexLocation {
    fn bundle(apk_part: String, dex_file: String) -> Self {
        Self {
            apk_part,
            dex_file,
            standalone: false,
        }
    }

    fn standalone(path: &Path) -> Self {
        Self {
            apk_part: "standalone".to_string(),
            dex_file: path.display().to_string(),
            standalone: true,
        }
    }

    fn qualified_name(&self) -> String {
        format!("{}!{}", self.apk_part, self.dex_file)
    }
}

#[derive(Debug)]
struct SourceDex {
    location: DexLocation,
    raw: RawDex,
}

#[derive(Debug, Clone)]
struct ClassDefinition {
    origin: Arc<DexLocation>,
    superclass: Option<String>,
    interfaces: Vec<String>,
    methods: Vec<MethodDefinition>,
    fields: Vec<FieldDefinition>,
}

#[derive(Debug, Clone)]
struct MethodDefinition {
    origin: Arc<DexLocation>,
    name: String,
    parameters: Vec<String>,
    return_type: String,
    is_static: bool,
    is_direct: bool,
}

impl MethodDefinition {
    fn signature(&self, owner: &str) -> String {
        format_method_reference(owner, &self.name, &self.parameters, &self.return_type)
    }
}

#[derive(Debug, Clone)]
struct FieldDefinition {
    origin: Arc<DexLocation>,
    name: String,
    field_type: String,
    is_static: bool,
}

impl FieldDefinition {
    fn signature(&self, owner: &str) -> String {
        format_field_reference(owner, &self.name, &self.field_type)
    }
}

#[derive(Debug, Default)]
struct DefinitionIndex {
    classes: HashMap<String, ClassDefinition>,
}

impl DefinitionIndex {
    fn add_dex(&mut self, raw: &RawDex, origin: &DexLocation) {
        let origin = Arc::new(origin.clone());
        for class in &raw.classes {
            let mut definition = build_class_definition(raw, class, &origin);
            match self.classes.get_mut(&class.class_type) {
                Some(existing) => {
                    existing.methods.append(&mut definition.methods);
                    existing.fields.append(&mut definition.fields);
                    existing.methods.sort_by(method_definition_order);
                    existing.methods.dedup_by(same_method_definition);
                    existing.fields.sort_by(field_definition_order);
                    existing.fields.dedup_by(same_field_definition);
                }
                None => {
                    self.classes.insert(class.class_type.clone(), definition);
                }
            }
        }
    }

    fn method_count(&self) -> usize {
        self.classes.values().map(|class| class.methods.len()).sum()
    }

    fn field_count(&self) -> usize {
        self.classes.values().map(|class| class.fields.len()).sum()
    }

    fn resolve_class(&self, descriptor: &str) -> MemberResolution {
        let Some(descriptor) = object_descriptor(descriptor) else {
            return MemberResolution::Resolved(None);
        };
        match self.classes.get(descriptor) {
            Some(class) => MemberResolution::Resolved(Some(class.origin.clone())),
            None => MemberResolution::Missing {
                reason: MissingReason::MissingOwner,
                candidates: Vec::new(),
            },
        }
    }

    fn resolve_method(&self, method: &MethodId, dispatch: MethodDispatch) -> MemberResolution {
        if !self.classes.contains_key(&method.class_type) {
            return MemberResolution::Missing {
                reason: MissingReason::MissingOwner,
                candidates: Vec::new(),
            };
        }

        let declared_only = dispatch != MethodDispatch::Virtual || method.name == "<init>";
        let owners = self.member_search_order(&method.class_type, declared_only);
        let mut named_candidates = Vec::new();
        let mut kind_mismatch = false;

        for owner in owners {
            let Some(class) = self.classes.get(&owner) else {
                continue;
            };
            for definition in &class.methods {
                if definition.name != method.name {
                    continue;
                }
                named_candidates.push(definition.signature(&owner));
                if definition.parameters == method.proto.parameters
                    && definition.return_type == method.proto.return_type
                {
                    if method_kind_matches(definition, dispatch, &method.name) {
                        return MemberResolution::Resolved(Some(definition.origin.clone()));
                    }
                    kind_mismatch = true;
                }
            }
        }

        named_candidates.sort();
        named_candidates.dedup();
        let reason = if kind_mismatch {
            MissingReason::MemberKindMismatch
        } else if named_candidates.is_empty() {
            MissingReason::MissingMethod
        } else {
            MissingReason::ChangedPrototype
        };
        MemberResolution::Missing {
            reason,
            candidates: named_candidates,
        }
    }

    fn resolve_field(&self, field: &FieldId, is_static: bool) -> MemberResolution {
        if !self.classes.contains_key(&field.class_type) {
            return MemberResolution::Missing {
                reason: MissingReason::MissingOwner,
                candidates: Vec::new(),
            };
        }

        let owners = self.member_search_order(&field.class_type, is_static);
        let mut named_candidates = Vec::new();
        let mut kind_mismatch = false;

        for owner in owners {
            let Some(class) = self.classes.get(&owner) else {
                continue;
            };
            for definition in &class.fields {
                if definition.name != field.name {
                    continue;
                }
                named_candidates.push(definition.signature(&owner));
                if definition.field_type == field.field_type {
                    if definition.is_static == is_static {
                        return MemberResolution::Resolved(Some(definition.origin.clone()));
                    }
                    kind_mismatch = true;
                }
            }
        }

        named_candidates.sort();
        named_candidates.dedup();
        let reason = if kind_mismatch {
            MissingReason::MemberKindMismatch
        } else if named_candidates.is_empty() {
            MissingReason::MissingField
        } else {
            MissingReason::ChangedDescriptor
        };
        MemberResolution::Missing {
            reason,
            candidates: named_candidates,
        }
    }

    fn member_search_order(&self, owner: &str, declared_only: bool) -> Vec<String> {
        if declared_only {
            return vec![owner.to_string()];
        }

        let mut order = Vec::new();
        let mut pending = vec![owner.to_string()];
        let mut visited = HashSet::new();
        while let Some(current) = pending.pop() {
            if !visited.insert(current.clone()) {
                continue;
            }
            order.push(current.clone());
            let Some(class) = self.classes.get(&current) else {
                continue;
            };
            for interface in class.interfaces.iter().rev() {
                pending.push(interface.clone());
            }
            if let Some(superclass) = &class.superclass {
                pending.push(superclass.clone());
            }
        }
        order
    }

    fn mapped_member_candidates(
        &self,
        kind: ReferenceKind,
        owner: &str,
        name: Option<&str>,
        mappings: &BTreeMap<String, String>,
    ) -> Vec<String> {
        let Some(mapped_owner) = mappings.get(owner) else {
            return Vec::new();
        };
        let mut candidates = vec![format!("mapped_owner={mapped_owner}")];
        let Some(class) = self.classes.get(mapped_owner) else {
            return candidates;
        };
        if let Some(name) = name {
            match kind {
                ReferenceKind::Class => {}
                ReferenceKind::Method => candidates.extend(
                    class
                        .methods
                        .iter()
                        .filter(|method| method.name == name)
                        .map(|method| method.signature(mapped_owner)),
                ),
                ReferenceKind::Field => candidates.extend(
                    class
                        .fields
                        .iter()
                        .filter(|field| field.name == name)
                        .map(|field| field.signature(mapped_owner)),
                ),
            }
        }
        candidates.sort();
        candidates.dedup();
        candidates
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MethodDispatch {
    Virtual,
    Direct,
    Static,
}

#[derive(Debug)]
enum MemberResolution {
    Resolved(Option<Arc<DexLocation>>),
    Missing {
        reason: MissingReason,
        candidates: Vec<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ReferenceKind {
    Class,
    Field,
    Method,
}

impl ReferenceKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Class => "class",
            Self::Field => "field",
            Self::Method => "method",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum MissingReason {
    MissingOwner,
    MissingMethod,
    MissingField,
    ChangedPrototype,
    ChangedDescriptor,
    MemberKindMismatch,
}

impl MissingReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::MissingOwner => "missing_owner",
            Self::MissingMethod => "missing_method",
            Self::MissingField => "missing_field",
            Self::ChangedPrototype => "changed_prototype",
            Self::ChangedDescriptor => "changed_descriptor",
            Self::MemberKindMismatch => "member_kind_mismatch",
        }
    }
}

#[derive(Debug, Clone)]
struct ReferenceSite {
    source: DexLocation,
    source_class: String,
    source_method: String,
    offset_code_unit: Option<u32>,
}

#[derive(Debug, Clone)]
struct UnresolvedReference {
    kind: ReferenceKind,
    reference: String,
    reason: MissingReason,
    site: ReferenceSite,
    candidates: Vec<String>,
}

#[derive(Debug, Default)]
struct AuditStats {
    target_parts: usize,
    target_dex_files: usize,
    source_dex_files: usize,
    standalone_reference_dex_files: usize,
    class_definitions: usize,
    method_definitions: usize,
    field_definitions: usize,
    references_scanned: usize,
    references_excluded: usize,
    references_resolved: usize,
    references_resolved_in_another_split: usize,
}

#[derive(Debug)]
struct AuditReport {
    target: PathBuf,
    allow_missing: usize,
    stats: AuditStats,
    unresolved: Vec<UnresolvedReference>,
}

impl AuditReport {
    fn passes(&self) -> bool {
        self.unresolved.len() <= self.allow_missing
    }
}

#[derive(Debug)]
struct PrefixPolicy {
    ignored: Vec<String>,
    included: Vec<String>,
}

impl PrefixPolicy {
    fn new(ignored: &[String], included: &[String]) -> Result<Self> {
        validate_prefixes("--ignore-prefix", ignored)?;
        validate_prefixes("--include-prefix", included)?;
        let mut all_ignored = DEFAULT_IGNORED_PREFIXES
            .iter()
            .map(|prefix| (*prefix).to_string())
            .collect::<Vec<_>>();
        all_ignored.extend(ignored.iter().cloned());
        all_ignored.sort();
        all_ignored.dedup();

        let mut included = included.to_vec();
        included.sort();
        included.dedup();
        Ok(Self {
            ignored: all_ignored,
            included,
        })
    }

    fn excludes(&self, descriptor: &str) -> bool {
        let Some(descriptor) = object_descriptor(descriptor) else {
            return true;
        };
        if self
            .included
            .iter()
            .any(|prefix| descriptor.starts_with(prefix))
        {
            return false;
        }
        self.ignored
            .iter()
            .any(|prefix| descriptor.starts_with(prefix))
    }
}

pub fn run(config: AuditRefsConfig) -> Result<()> {
    validate_sources(&config)?;
    let policy = PrefixPolicy::new(&config.ignore_prefixes, &config.include_prefixes)?;
    let mappings = match &config.mapping {
        Some(path) => crate::remap::load_safe_descriptor_mappings(path)?,
        None => BTreeMap::new(),
    };
    let progress = crate::progress::Progress::new(config.progress);
    let mut progress = progress;
    progress.set_total(4);

    progress.stage_stats("resolve input", config.target.display().to_string());
    let mut index = DefinitionIndex::default();
    let (mut sources, mut stats) = load_target_dexes(&config, &mut index)?;
    load_standalone_sources(&config.references, &mut index, &mut sources, &mut stats)?;
    stats.class_definitions = index.classes.len();
    stats.method_definitions = index.method_count();
    stats.field_definitions = index.field_count();

    progress.stage_stats(
        "index definitions",
        format!(
            "classes={} methods={} fields={}",
            stats.class_definitions, stats.method_definitions, stats.field_definitions
        ),
    );

    let mut unresolved = Vec::new();
    for source in &sources {
        audit_source_dex(
            source,
            &index,
            &policy,
            &mappings,
            &mut stats,
            &mut unresolved,
        );
    }
    unresolved.sort_by(unresolved_order);

    let report = AuditReport {
        target: config.target.clone(),
        allow_missing: config.allow_missing,
        stats,
        unresolved,
    };
    progress.stage_stats(
        "audit references",
        format!(
            "resolved={} unresolved={} excluded={}",
            report.stats.references_resolved,
            report.unresolved.len(),
            report.stats.references_excluded
        ),
    );

    progress.stage_stats("report", config.output.display().to_string());
    write_report(&config.output, &report)?;
    if report.passes() {
        Ok(())
    } else {
        Err(UnocRsError::ReferenceAuditFailed {
            unresolved: report.unresolved.len(),
            allowed: report.allow_missing,
            output: config.output,
        })
    }
}

fn validate_sources(config: &AuditRefsConfig) -> Result<()> {
    if config.source_dexes.is_empty() && config.references.is_empty() {
        return Err(UnocRsError::MissingAuditSources);
    }
    Ok(())
}

fn validate_prefixes(option: &str, prefixes: &[String]) -> Result<()> {
    if let Some(prefix) = prefixes.iter().find(|prefix| prefix.trim().is_empty()) {
        return Err(UnocRsError::InvalidAuditPrefix {
            option: option.to_string(),
            prefix: prefix.clone(),
        });
    }
    Ok(())
}

fn load_target_dexes(
    config: &AuditRefsConfig,
    index: &mut DefinitionIndex,
) -> Result<(Vec<SourceDex>, AuditStats)> {
    let resolved = resolve_app_input(&config.target)?;
    let mut stats = AuditStats {
        target_parts: resolved.parts.len(),
        ..AuditStats::default()
    };
    let mut sources = Vec::new();
    let mut matched_selectors = BTreeSet::new();

    for part in resolved.parts {
        let apk = match read_apk_part_from_resolved(&resolved.source_path, part) {
            Ok(apk) => apk,
            Err(UnocRsError::NoDexFiles(_)) => continue,
            Err(error) => return Err(error),
        };
        for dex in apk.dex_files {
            stats.target_dex_files += 1;
            let location = DexLocation::bundle(dex.apk_part.clone(), dex.name.clone());
            let parsed = crate::dex::parse_dex(&dex.bytes)?;
            index.add_dex(&parsed.raw, &location);
            let matching = config
                .source_dexes
                .iter()
                .filter(|selector| source_selector_matches(selector, &location))
                .cloned()
                .collect::<Vec<_>>();
            if !matching.is_empty() {
                validate_audit_source(&parsed.raw, &location)?;
                matched_selectors.extend(matching);
                sources.push(SourceDex {
                    location,
                    raw: parsed.raw,
                });
                stats.source_dex_files += 1;
            }
        }
    }

    let missing = config
        .source_dexes
        .iter()
        .filter(|selector| !matched_selectors.contains(*selector))
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(UnocRsError::AuditSourceDexNotFound {
            selectors: missing.join(", "),
        });
    }
    Ok((sources, stats))
}

fn load_standalone_sources(
    paths: &[PathBuf],
    index: &mut DefinitionIndex,
    sources: &mut Vec<SourceDex>,
    stats: &mut AuditStats,
) -> Result<()> {
    for path in paths {
        if !path.is_file() {
            return Err(UnocRsError::MissingInput(path.clone()));
        }
        let bytes = fs::read(path)?;
        let parsed = crate::dex::parse_dex(&bytes)?;
        let location = DexLocation::standalone(path);
        validate_audit_source(&parsed.raw, &location)?;
        index.add_dex(&parsed.raw, &location);
        sources.push(SourceDex {
            location,
            raw: parsed.raw,
        });
        stats.standalone_reference_dex_files += 1;
    }
    Ok(())
}

fn validate_audit_source(raw: &RawDex, location: &DexLocation) -> Result<()> {
    let incomplete = |reason| UnocRsError::IncompleteAuditSource {
        origin: location.qualified_name(),
        reason,
    };
    if let Some(warning) = raw.warnings.first() {
        return Err(incomplete(format!(
            "{} warning(s); {}: {}",
            raw.warnings.len(),
            warning.origin,
            warning.message
        )));
    }

    for class in &raw.classes {
        let Some(data) = &class.class_data else {
            continue;
        };
        for field in data.static_fields.iter().chain(&data.instance_fields) {
            if raw.fields.get(field.field_idx as usize).is_none() {
                return Err(incomplete(format!(
                    "{}: declared field index {} is out of range",
                    class.class_type, field.field_idx
                )));
            }
        }
        for method in data.direct_methods.iter().chain(&data.virtual_methods) {
            if raw.methods.get(method.method_idx as usize).is_none() {
                return Err(incomplete(format!(
                    "{}: declared method index {} is out of range",
                    class.class_type, method.method_idx
                )));
            }
            if method.code_off == 0 {
                continue;
            }
            let code = raw.code_items.get(&method.code_off).ok_or_else(|| {
                incomplete(format!(
                    "{}: missing code item at offset {}",
                    class.class_type, method.code_off
                ))
            })?;
            let summary = &code.instruction_summary;
            for (kind, references, count) in [
                ("type", &summary.type_ref_uses, raw.types.len()),
                ("method", &summary.method_ref_uses, raw.methods.len()),
                ("field", &summary.field_ref_uses, raw.fields.len()),
            ] {
                if let Some(reference) = references
                    .iter()
                    .find(|reference| reference.index as usize >= count)
                {
                    return Err(incomplete(format!(
                        "{}@code_off={}: {kind} reference index {} at code-unit {} is out of range",
                        class.class_type,
                        method.code_off,
                        reference.index,
                        reference.offset_code_unit
                    )));
                }
            }
        }
    }
    Ok(())
}

fn source_selector_matches(selector: &str, location: &DexLocation) -> bool {
    selector == location.dex_file || selector == location.qualified_name()
}

fn read_apk_part_from_resolved(source_path: &Path, part: ApkPart) -> Result<ApkInput> {
    if let Some(path) = part.path {
        read_apk_part(&path, &part.part_name)
    } else {
        read_apk_part_bytes(source_path, &part.part_name, part.bytes)
    }
}

fn audit_source_dex(
    source: &SourceDex,
    index: &DefinitionIndex,
    policy: &PrefixPolicy,
    mappings: &BTreeMap<String, String>,
    stats: &mut AuditStats,
    unresolved: &mut Vec<UnresolvedReference>,
) {
    for class in &source.raw.classes {
        let class_site = ReferenceSite {
            source: source.location.clone(),
            source_class: class.class_type.clone(),
            source_method: "-".to_string(),
            offset_code_unit: None,
        };
        if let Some(superclass) = &class.superclass {
            audit_class_reference(
                superclass,
                class_site.clone(),
                index,
                policy,
                mappings,
                stats,
                unresolved,
            );
        }
        for interface in &class.interfaces {
            audit_class_reference(
                interface,
                class_site.clone(),
                index,
                policy,
                mappings,
                stats,
                unresolved,
            );
        }
        audit_declared_members(source, class, index, policy, mappings, stats, unresolved);
    }
}

#[allow(clippy::too_many_arguments)]
fn audit_declared_members(
    source: &SourceDex,
    class: &ClassDef,
    index: &DefinitionIndex,
    policy: &PrefixPolicy,
    mappings: &BTreeMap<String, String>,
    stats: &mut AuditStats,
    unresolved: &mut Vec<UnresolvedReference>,
) {
    let Some(class_data) = &class.class_data else {
        return;
    };

    for encoded in class_data
        .static_fields
        .iter()
        .chain(class_data.instance_fields.iter())
    {
        let Some(field) = source.raw.fields.get(encoded.field_idx as usize) else {
            continue;
        };
        let site = ReferenceSite {
            source: source.location.clone(),
            source_class: class.class_type.clone(),
            source_method: format!("{}:{}", field.name, field.field_type),
            offset_code_unit: None,
        };
        audit_class_reference(
            &field.field_type,
            site,
            index,
            policy,
            mappings,
            stats,
            unresolved,
        );
    }

    for encoded in class_data
        .direct_methods
        .iter()
        .chain(class_data.virtual_methods.iter())
    {
        let Some(method) = source.raw.methods.get(encoded.method_idx as usize) else {
            continue;
        };
        let source_method = format_method_reference(
            &class.class_type,
            &method.name,
            &method.proto.parameters,
            &method.proto.return_type,
        );
        let declaration_site = ReferenceSite {
            source: source.location.clone(),
            source_class: class.class_type.clone(),
            source_method: source_method.clone(),
            offset_code_unit: None,
        };
        audit_class_reference(
            &method.proto.return_type,
            declaration_site.clone(),
            index,
            policy,
            mappings,
            stats,
            unresolved,
        );
        for parameter in &method.proto.parameters {
            audit_class_reference(
                parameter,
                declaration_site.clone(),
                index,
                policy,
                mappings,
                stats,
                unresolved,
            );
        }

        let Some(code) = source.raw.code_items.get(&encoded.code_off) else {
            continue;
        };
        audit_instruction_references(
            source,
            class,
            &source_method,
            &code.instruction_summary.type_ref_uses,
            &code.instruction_summary.method_ref_uses,
            &code.instruction_summary.field_ref_uses,
            index,
            policy,
            mappings,
            stats,
            unresolved,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn audit_instruction_references(
    source: &SourceDex,
    class: &ClassDef,
    source_method: &str,
    type_references: &[InstructionReference],
    method_references: &[InstructionReference],
    field_references: &[InstructionReference],
    index: &DefinitionIndex,
    policy: &PrefixPolicy,
    mappings: &BTreeMap<String, String>,
    stats: &mut AuditStats,
    unresolved: &mut Vec<UnresolvedReference>,
) {
    for reference in type_references {
        let Some(descriptor) = source.raw.types.get(reference.index as usize) else {
            continue;
        };
        audit_class_reference(
            descriptor,
            instruction_site(source, class, source_method, reference),
            index,
            policy,
            mappings,
            stats,
            unresolved,
        );
    }

    for reference in method_references {
        let Some(method) = source.raw.methods.get(reference.index as usize) else {
            continue;
        };
        audit_method_reference(
            method,
            method_dispatch(reference.opcode),
            instruction_site(source, class, source_method, reference),
            index,
            policy,
            mappings,
            stats,
            unresolved,
        );
    }

    for reference in field_references {
        let Some(field) = source.raw.fields.get(reference.index as usize) else {
            continue;
        };
        audit_field_reference(
            field,
            is_static_field_opcode(reference.opcode),
            instruction_site(source, class, source_method, reference),
            index,
            policy,
            mappings,
            stats,
            unresolved,
        );
    }
}

fn instruction_site(
    source: &SourceDex,
    class: &ClassDef,
    source_method: &str,
    reference: &InstructionReference,
) -> ReferenceSite {
    ReferenceSite {
        source: source.location.clone(),
        source_class: class.class_type.clone(),
        source_method: source_method.to_string(),
        offset_code_unit: Some(reference.offset_code_unit),
    }
}

#[allow(clippy::too_many_arguments)]
fn audit_class_reference(
    descriptor: &str,
    site: ReferenceSite,
    index: &DefinitionIndex,
    policy: &PrefixPolicy,
    mappings: &BTreeMap<String, String>,
    stats: &mut AuditStats,
    unresolved: &mut Vec<UnresolvedReference>,
) {
    let Some(owner) = object_descriptor(descriptor) else {
        return;
    };
    stats.references_scanned += 1;
    if policy.excludes(owner) {
        stats.references_excluded += 1;
        return;
    }
    let resolution = index.resolve_class(owner);
    record_resolution(
        ReferenceKind::Class,
        owner.to_string(),
        owner,
        None,
        site,
        resolution,
        index,
        mappings,
        stats,
        unresolved,
    );
}

#[allow(clippy::too_many_arguments)]
fn audit_method_reference(
    method: &MethodId,
    dispatch: MethodDispatch,
    site: ReferenceSite,
    index: &DefinitionIndex,
    policy: &PrefixPolicy,
    mappings: &BTreeMap<String, String>,
    stats: &mut AuditStats,
    unresolved: &mut Vec<UnresolvedReference>,
) {
    audit_class_reference(
        &method.proto.return_type,
        site.clone(),
        index,
        policy,
        mappings,
        stats,
        unresolved,
    );
    for parameter in &method.proto.parameters {
        audit_class_reference(
            parameter,
            site.clone(),
            index,
            policy,
            mappings,
            stats,
            unresolved,
        );
    }

    stats.references_scanned += 1;
    if policy.excludes(&method.class_type) {
        stats.references_excluded += 1;
        return;
    }
    let reference = format_method_reference(
        &method.class_type,
        &method.name,
        &method.proto.parameters,
        &method.proto.return_type,
    );
    let resolution = index.resolve_method(method, dispatch);
    record_resolution(
        ReferenceKind::Method,
        reference,
        &method.class_type,
        Some(&method.name),
        site,
        resolution,
        index,
        mappings,
        stats,
        unresolved,
    );
}

#[allow(clippy::too_many_arguments)]
fn audit_field_reference(
    field: &FieldId,
    is_static: bool,
    site: ReferenceSite,
    index: &DefinitionIndex,
    policy: &PrefixPolicy,
    mappings: &BTreeMap<String, String>,
    stats: &mut AuditStats,
    unresolved: &mut Vec<UnresolvedReference>,
) {
    audit_class_reference(
        &field.field_type,
        site.clone(),
        index,
        policy,
        mappings,
        stats,
        unresolved,
    );

    stats.references_scanned += 1;
    if policy.excludes(&field.class_type) {
        stats.references_excluded += 1;
        return;
    }
    let reference = format_field_reference(&field.class_type, &field.name, &field.field_type);
    let resolution = index.resolve_field(field, is_static);
    record_resolution(
        ReferenceKind::Field,
        reference,
        &field.class_type,
        Some(&field.name),
        site,
        resolution,
        index,
        mappings,
        stats,
        unresolved,
    );
}

#[allow(clippy::too_many_arguments)]
fn record_resolution(
    kind: ReferenceKind,
    reference: String,
    owner: &str,
    member_name: Option<&str>,
    site: ReferenceSite,
    resolution: MemberResolution,
    index: &DefinitionIndex,
    mappings: &BTreeMap<String, String>,
    stats: &mut AuditStats,
    unresolved: &mut Vec<UnresolvedReference>,
) {
    match resolution {
        MemberResolution::Resolved(origin) => {
            stats.references_resolved += 1;
            if origin
                .as_ref()
                .is_some_and(|origin| resolved_in_another_split(&site.source, origin))
            {
                stats.references_resolved_in_another_split += 1;
            }
        }
        MemberResolution::Missing {
            reason,
            mut candidates,
        } => {
            candidates.extend(index.mapped_member_candidates(kind, owner, member_name, mappings));
            candidates.sort();
            candidates.dedup();
            unresolved.push(UnresolvedReference {
                kind,
                reference,
                reason,
                site,
                candidates,
            });
        }
    }
}

fn resolved_in_another_split(source: &DexLocation, target: &DexLocation) -> bool {
    !source.standalone && !target.standalone && source.apk_part != target.apk_part
}

fn build_class_definition(
    raw: &RawDex,
    class: &ClassDef,
    origin: &Arc<DexLocation>,
) -> ClassDefinition {
    let mut methods = Vec::new();
    let mut fields = Vec::new();
    if let Some(class_data) = &class.class_data {
        fields.extend(
            class_data
                .static_fields
                .iter()
                .filter_map(|encoded| raw.fields.get(encoded.field_idx as usize))
                .map(|field| FieldDefinition {
                    origin: origin.clone(),
                    name: field.name.clone(),
                    field_type: field.field_type.clone(),
                    is_static: true,
                }),
        );
        fields.extend(
            class_data
                .instance_fields
                .iter()
                .filter_map(|encoded| raw.fields.get(encoded.field_idx as usize))
                .map(|field| FieldDefinition {
                    origin: origin.clone(),
                    name: field.name.clone(),
                    field_type: field.field_type.clone(),
                    is_static: false,
                }),
        );
        methods.extend(
            class_data
                .direct_methods
                .iter()
                .filter_map(|encoded| {
                    raw.methods
                        .get(encoded.method_idx as usize)
                        .map(|method| (encoded, method))
                })
                .map(|(encoded, method)| MethodDefinition {
                    origin: origin.clone(),
                    name: method.name.clone(),
                    parameters: method.proto.parameters.clone(),
                    return_type: method.proto.return_type.clone(),
                    is_static: encoded.access_flags & ACC_STATIC != 0,
                    is_direct: true,
                }),
        );
        methods.extend(
            class_data
                .virtual_methods
                .iter()
                .filter_map(|encoded| {
                    raw.methods
                        .get(encoded.method_idx as usize)
                        .map(|method| (encoded, method))
                })
                .map(|(encoded, method)| MethodDefinition {
                    origin: origin.clone(),
                    name: method.name.clone(),
                    parameters: method.proto.parameters.clone(),
                    return_type: method.proto.return_type.clone(),
                    is_static: encoded.access_flags & ACC_STATIC != 0,
                    is_direct: false,
                }),
        );
    }
    ClassDefinition {
        origin: origin.clone(),
        superclass: class.superclass.clone(),
        interfaces: class.interfaces.clone(),
        methods,
        fields,
    }
}

fn method_definition_order(
    left: &MethodDefinition,
    right: &MethodDefinition,
) -> std::cmp::Ordering {
    left.name
        .cmp(&right.name)
        .then(left.parameters.cmp(&right.parameters))
        .then(left.return_type.cmp(&right.return_type))
        .then(left.is_static.cmp(&right.is_static))
        .then(left.is_direct.cmp(&right.is_direct))
}

fn same_method_definition(left: &mut MethodDefinition, right: &mut MethodDefinition) -> bool {
    method_definition_order(left, right).is_eq()
}

fn field_definition_order(left: &FieldDefinition, right: &FieldDefinition) -> std::cmp::Ordering {
    left.name
        .cmp(&right.name)
        .then(left.field_type.cmp(&right.field_type))
        .then(left.is_static.cmp(&right.is_static))
}

fn same_field_definition(left: &mut FieldDefinition, right: &mut FieldDefinition) -> bool {
    field_definition_order(left, right).is_eq()
}

fn method_kind_matches(
    definition: &MethodDefinition,
    dispatch: MethodDispatch,
    name: &str,
) -> bool {
    match dispatch {
        MethodDispatch::Static => definition.is_static,
        MethodDispatch::Direct => !definition.is_static && definition.is_direct,
        MethodDispatch::Virtual => {
            !definition.is_static && !definition.is_direct && name != "<init>"
        }
    }
}

fn method_dispatch(opcode: u8) -> MethodDispatch {
    match opcode {
        0x71 | 0x77 => MethodDispatch::Static,
        0x70 | 0x76 => MethodDispatch::Direct,
        _ => MethodDispatch::Virtual,
    }
}

fn is_static_field_opcode(opcode: u8) -> bool {
    matches!(opcode, 0x60..=0x6d)
}

fn object_descriptor(descriptor: &str) -> Option<&str> {
    let descriptor = descriptor.trim_start_matches('[');
    descriptor.starts_with('L').then_some(descriptor)
}

fn format_method_reference(
    owner: &str,
    name: &str,
    parameters: &[String],
    return_type: &str,
) -> String {
    format!("{owner}->{name}({}){return_type}", parameters.join(""))
}

fn format_field_reference(owner: &str, name: &str, field_type: &str) -> String {
    format!("{owner}->{name}:{field_type}")
}

fn unresolved_order(left: &UnresolvedReference, right: &UnresolvedReference) -> std::cmp::Ordering {
    left.reason
        .cmp(&right.reason)
        .then(left.kind.cmp(&right.kind))
        .then(left.reference.cmp(&right.reference))
        .then(left.site.source.apk_part.cmp(&right.site.source.apk_part))
        .then(left.site.source.dex_file.cmp(&right.site.source.dex_file))
        .then(left.site.source_class.cmp(&right.site.source_class))
        .then(left.site.source_method.cmp(&right.site.source_method))
        .then(left.site.offset_code_unit.cmp(&right.site.offset_code_unit))
}

fn write_report(output: &Path, report: &AuditReport) -> Result<()> {
    fs::create_dir_all(output)?;
    fs::write(output.join("summary.txt"), render_summary(report))?;
    let file = fs::File::create(output.join("unresolved-refs.tsv"))?;
    let mut writer = BufWriter::new(file);
    writeln!(
        writer,
        "kind\treference\treason\tsource_split\tsource_dex\tsource_class\tsource_method\toffset\tcandidates"
    )?;
    for item in &report.unresolved {
        let offset = item
            .site
            .offset_code_unit
            .map(|offset| format!("0x{offset:x}"))
            .unwrap_or_else(|| "-".to_string());
        writeln!(
            writer,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            item.kind.as_str(),
            tsv_cell(&item.reference),
            item.reason.as_str(),
            tsv_cell(&item.site.source.apk_part),
            tsv_cell(&item.site.source.dex_file),
            tsv_cell(&item.site.source_class),
            tsv_cell(&item.site.source_method),
            offset,
            tsv_cell(&item.candidates.join(" | "))
        )?;
    }
    writer.flush()?;
    Ok(())
}

fn render_summary(report: &AuditReport) -> String {
    let mut output = String::new();
    writeln!(output, "unoc-rs Reference Audit").expect("write string");
    writeln!(output, "=======================").expect("write string");
    writeln!(output).expect("write string");
    writeln!(output, "target: {}", report.target.display()).expect("write string");
    writeln!(output, "target_parts: {}", report.stats.target_parts).expect("write string");
    writeln!(
        output,
        "target_dex_files: {}",
        report.stats.target_dex_files
    )
    .expect("write string");
    writeln!(
        output,
        "source_dex_files: {}",
        report.stats.source_dex_files
    )
    .expect("write string");
    writeln!(
        output,
        "standalone_reference_dex_files: {}",
        report.stats.standalone_reference_dex_files
    )
    .expect("write string");
    writeln!(
        output,
        "class_definitions: {}",
        report.stats.class_definitions
    )
    .expect("write string");
    writeln!(
        output,
        "method_definitions: {}",
        report.stats.method_definitions
    )
    .expect("write string");
    writeln!(
        output,
        "field_definitions: {}",
        report.stats.field_definitions
    )
    .expect("write string");
    writeln!(
        output,
        "references_scanned: {}",
        report.stats.references_scanned
    )
    .expect("write string");
    writeln!(
        output,
        "references_excluded: {}",
        report.stats.references_excluded
    )
    .expect("write string");
    writeln!(
        output,
        "references_resolved: {}",
        report.stats.references_resolved
    )
    .expect("write string");
    writeln!(
        output,
        "resolved_in_another_split: {}",
        report.stats.references_resolved_in_another_split
    )
    .expect("write string");
    writeln!(output, "unresolved_references: {}", report.unresolved.len()).expect("write string");
    writeln!(output, "allow_missing: {}", report.allow_missing).expect("write string");
    writeln!(
        output,
        "status: {}",
        if report.passes() { "PASS" } else { "FAIL" }
    )
    .expect("write string");

    let mut reason_counts = BTreeMap::new();
    for item in &report.unresolved {
        *reason_counts.entry(item.reason).or_insert(0usize) += 1;
    }
    if !reason_counts.is_empty() {
        writeln!(output).expect("write string");
        writeln!(output, "Unresolved by reason").expect("write string");
        writeln!(output, "--------------------").expect("write string");
        for (reason, count) in reason_counts {
            writeln!(output, "{}: {}", reason.as_str(), count).expect("write string");
        }
    }
    output
}

fn tsv_cell(value: &str) -> String {
    value.replace(['\t', '\n', '\r'], " ")
}

#[cfg(test)]
mod tests {
    use super::{object_descriptor, PrefixPolicy};

    #[test]
    fn platform_prefixes_are_ignored_unless_included() {
        let default = PrefixPolicy::new(&[], &[]).expect("default policy");
        assert!(default.excludes("Ljava/lang/String;"));

        let included = PrefixPolicy::new(&[], &["Ljava/".to_string()]).expect("included policy");
        assert!(!included.excludes("Ljava/lang/String;"));
    }

    #[test]
    fn array_descriptors_resolve_their_object_component() {
        assert_eq!(
            object_descriptor("[[Lexample/Value;"),
            Some("Lexample/Value;")
        );
        assert_eq!(object_descriptor("[I"), None);
    }
}
