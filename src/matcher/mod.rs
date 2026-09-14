pub mod score;

use std::collections::{BTreeMap, BTreeSet};

use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::fingerprint::{AppFingerprint, ClassFingerprint};
use crate::matcher::score::{
    bounded_ratio, equal_score, exact_option, histogram_cosine_u8, jaccard, signal_jaccard,
};
use crate::model::{AppModel, ClassModel, FieldModel, MethodModel};

pub const RARE_ANCHOR_MAX_FREQUENCY: usize = 3;
pub const CALL_GRAPH_VERIFY_PASSES: usize = 2;

pub const VERIFIED_EXACT_CLASS_FINGERPRINT: &str = "verified: exact class fingerprint";
pub const VERIFIED_EXACT_DESCRIPTOR_STABLE_API: &str =
    "verified: exact descriptor and stable API shape";
pub const VERIFIED_EXACT_DESCRIPTOR_STABLE_CODE: &str =
    "verified: exact descriptor and stable code pattern";
pub const VERIFIED_EXACT_DESCRIPTOR_STABLE_PROTO_CODE: &str =
    "verified: exact descriptor and stable proto/code pattern";
pub const VERIFIED_RENAMED_EXACT_BEHAVIOR: &str = "verified: renamed exact behavior pattern";
pub const VERIFIED_RENAMED_STABLE_PROTO_ANCHOR: &str =
    "verified: renamed stable prototype and anchor pattern";
pub const VERIFIED_RARE_ANCHORS_STABLE_SHAPE: &str = "verified: rare anchors and stable shape";
pub const VERIFIED_CALL_GRAPH_NEIGHBORHOOD: &str = "verified: call graph neighborhood";
pub const SEMANTIC_BREAK_CLASS_KIND: &str = "semantic break: class/interface access flag changed";
pub const UNSAFE_SAME_DESCRIPTOR_WEAK_SHAPE: &str =
    "unsafe same descriptor: weak method shape overlap";
pub const CONFLICT_SHARED_NEW_CLASS: &str =
    "conflict: multiple old classes select the same new class";

const ACC_INTERFACE: u32 = 0x0200;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MatchStatus {
    Matched,
    LowConfidence,
    Conflict,
    SemanticBreak,
    UnresolvedOld,
    UnresolvedNew,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClassMatch {
    pub old_class_id: Option<usize>,
    pub new_class_id: Option<usize>,
    pub score: f32,
    pub status: MatchStatus,
    pub reasons: Vec<String>,
    pub candidates: Vec<Candidate>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MemberMatch {
    pub old_owner_class_id: Option<usize>,
    pub new_owner_class_id: Option<usize>,
    pub old_member_id: Option<usize>,
    pub new_member_id: Option<usize>,
    pub score: f32,
    pub status: MatchStatus,
    pub reasons: Vec<String>,
    pub candidates: Vec<Candidate>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MatchReport {
    pub classes: Vec<ClassMatch>,
    pub methods: Vec<MemberMatch>,
    pub fields: Vec<MemberMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Candidate {
    pub entity_id: usize,
    pub score: f32,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct MatchConfig {
    pub min_confidence: f32,
    pub low_confidence: f32,
    pub max_candidates: usize,
    pub verified_only: bool,
}

pub fn match_classes(
    old: &AppFingerprint,
    new: &AppFingerprint,
    config: &MatchConfig,
) -> Vec<ClassMatch> {
    let context = MatchContext::new(old, new);
    let index = ClassCandidateIndex::new(&new.classes);
    let mut matches: Vec<ClassMatch> = old
        .classes
        .par_iter()
        .map(|old_class| match_one_class(old_class, &index, &context, config))
        .collect();

    // Conflicting mappings must not act as verified seeds for their neighbors.
    mark_shared_new_classes(&mut matches);
    run_call_graph_verification(&mut matches, old, new, config);

    let matched_new: std::collections::BTreeSet<_> = matches
        .iter()
        .filter(|item| {
            matches!(
                item.status,
                MatchStatus::Matched
                    | MatchStatus::LowConfidence
                    | MatchStatus::Conflict
                    | MatchStatus::SemanticBreak
            )
        })
        .filter_map(|item| item.new_class_id)
        .collect();

    for new_class in &new.classes {
        if !matched_new.contains(&new_class.class_id) {
            matches.push(ClassMatch {
                old_class_id: None,
                new_class_id: Some(new_class.class_id),
                score: 0.0,
                status: MatchStatus::UnresolvedNew,
                reasons: vec!["no old candidate above low-confidence threshold".to_string()],
                candidates: Vec::new(),
            });
        }
    }

    propagate_scores(&mut matches);
    matches
}

pub fn match_apps(
    old_fp: &AppFingerprint,
    new_fp: &AppFingerprint,
    config: &MatchConfig,
) -> MatchReport {
    let classes = match_classes(old_fp, new_fp, config);
    MatchReport {
        classes,
        methods: Vec::new(),
        fields: Vec::new(),
    }
}

pub fn match_apps_low_memory(
    old_fp: &AppFingerprint,
    new_fp: &AppFingerprint,
    config: &MatchConfig,
) -> MatchReport {
    let classes = match_classes_exact_descriptors(old_fp, new_fp, config);
    MatchReport {
        classes,
        methods: Vec::new(),
        fields: Vec::new(),
    }
}

pub fn match_app_models(
    old_model: &AppModel,
    new_model: &AppModel,
    old_fp: &AppFingerprint,
    new_fp: &AppFingerprint,
    config: &MatchConfig,
) -> MatchReport {
    let classes = match_classes(old_fp, new_fp, config);
    let old_classes = classes_by_id(&old_model.classes);
    let new_classes = classes_by_id(&new_model.classes);
    let member_matches: Vec<_> = classes
        .par_iter()
        .filter(|class_match| {
            matches!(
                class_match.status,
                MatchStatus::Matched | MatchStatus::LowConfidence
            )
        })
        .filter_map(|class_match| {
            let old_class_id = class_match.old_class_id?;
            let new_class_id = class_match.new_class_id?;
            let old_class = old_classes
                .get(old_class_id)
                .and_then(|class| class.as_ref())?;
            let new_class = new_classes
                .get(new_class_id)
                .and_then(|class| class.as_ref())?;

            Some((
                match_methods_in_class(old_class, new_class, old_class_id, new_class_id, config),
                match_fields_in_class(old_class, new_class, old_class_id, new_class_id, config),
            ))
        })
        .collect();

    let mut methods = Vec::new();
    let mut fields = Vec::new();
    for (class_methods, class_fields) in member_matches {
        methods.extend(class_methods);
        fields.extend(class_fields);
    }

    methods.sort_by_key(|item| {
        (
            item.old_owner_class_id.unwrap_or(usize::MAX),
            item.old_member_id.unwrap_or(usize::MAX),
            item.new_member_id.unwrap_or(usize::MAX),
        )
    });
    fields.sort_by_key(|item| {
        (
            item.old_owner_class_id.unwrap_or(usize::MAX),
            item.old_member_id.unwrap_or(usize::MAX),
            item.new_member_id.unwrap_or(usize::MAX),
        )
    });

    MatchReport {
        classes,
        methods,
        fields,
    }
}

fn classes_by_id(classes: &[ClassModel]) -> Vec<Option<&ClassModel>> {
    let Some(max_id) = classes.iter().map(|class| class.id).max() else {
        return Vec::new();
    };
    let mut by_id = vec![None; max_id + 1];
    for class in classes {
        by_id[class.id] = Some(class);
    }
    by_id
}

fn fingerprints_by_id(classes: &[ClassFingerprint]) -> Vec<Option<&ClassFingerprint>> {
    let Some(max_id) = classes.iter().map(|class| class.class_id).max() else {
        return Vec::new();
    };
    let mut by_id = vec![None; max_id + 1];
    for class in classes {
        by_id[class.class_id] = Some(class);
    }
    by_id
}

fn match_classes_exact_descriptors(
    old: &AppFingerprint,
    new: &AppFingerprint,
    config: &MatchConfig,
) -> Vec<ClassMatch> {
    let context = MatchContext::new(old, new);
    let index = ClassCandidateIndex::new(&new.classes);
    let mut matches: Vec<_> = old
        .classes
        .par_iter()
        .map(|old_class| {
            let Some(new_class) = index.by_descriptor.get(old_class.descriptor.as_str()) else {
                return ClassMatch {
                    old_class_id: Some(old_class.class_id),
                    new_class_id: None,
                    score: 0.0,
                    status: MatchStatus::UnresolvedOld,
                    reasons: vec!["no exact descriptor match in low-memory mode".to_string()],
                    candidates: Vec::new(),
                };
            };
            let candidate = score_class(old_class, new_class, &context);
            if candidate.score >= config.low_confidence {
                class_match_from_candidates(old_class, vec![candidate], config)
            } else {
                ClassMatch {
                    old_class_id: Some(old_class.class_id),
                    new_class_id: None,
                    score: 0.0,
                    status: MatchStatus::UnresolvedOld,
                    reasons: vec![
                        "exact descriptor candidate below low-confidence threshold".to_string()
                    ],
                    candidates: Vec::new(),
                }
            }
        })
        .collect();

    mark_shared_new_classes(&mut matches);

    let matched_new: std::collections::BTreeSet<_> = matches
        .iter()
        .filter(|item| {
            matches!(
                item.status,
                MatchStatus::Matched
                    | MatchStatus::LowConfidence
                    | MatchStatus::Conflict
                    | MatchStatus::SemanticBreak
            )
        })
        .filter_map(|item| item.new_class_id)
        .collect();

    for new_class in &new.classes {
        if !matched_new.contains(&new_class.class_id) {
            matches.push(ClassMatch {
                old_class_id: None,
                new_class_id: Some(new_class.class_id),
                score: 0.0,
                status: MatchStatus::UnresolvedNew,
                reasons: vec!["no old exact descriptor match in low-memory mode".to_string()],
                candidates: Vec::new(),
            });
        }
    }

    propagate_scores(&mut matches);
    matches
}

fn mark_shared_new_classes(matches: &mut [ClassMatch]) {
    let claims = matches
        .iter()
        .filter(|item| {
            item.old_class_id.is_some()
                && matches!(
                    item.status,
                    MatchStatus::Matched | MatchStatus::LowConfidence | MatchStatus::Conflict
                )
        })
        .filter_map(|item| item.new_class_id)
        .fold(BTreeMap::new(), |mut counts, id| {
            *counts.entry(id).or_insert(0usize) += 1;
            counts
        });

    for item in matches {
        if item.old_class_id.is_some()
            && matches!(
                item.status,
                MatchStatus::Matched | MatchStatus::LowConfidence | MatchStatus::Conflict
            )
            && item
                .new_class_id
                .is_some_and(|id| claims.get(&id).is_some_and(|count| *count > 1))
        {
            item.status = MatchStatus::Conflict;
            item.reasons
                .retain(|reason| !reason.starts_with("verified:"));
            item.reasons.push(CONFLICT_SHARED_NEW_CLASS.to_string());
        }
    }
}

fn match_methods_in_class(
    old_class: &ClassModel,
    new_class: &ClassModel,
    old_class_id: usize,
    new_class_id: usize,
    config: &MatchConfig,
) -> Vec<MemberMatch> {
    let index = MethodCandidateIndex::new(&new_class.methods);
    let mut results = Vec::new();
    for old_method in &old_class.methods {
        let candidates = index.candidates(old_method, member_candidate_scan_limit(config));
        let result = match_one_member_candidates(
            old_class_id,
            new_class_id,
            old_method.id,
            candidates.into_iter(),
            config,
            |new_method| score_method(old_method, new_method),
        );
        results.push(result);
    }
    push_unresolved_new_members(
        &mut results,
        old_class_id,
        new_class_id,
        new_class.methods.iter().map(|method| method.id),
        "no old method candidate above low-confidence threshold",
    );
    results
}

fn match_fields_in_class(
    old_class: &ClassModel,
    new_class: &ClassModel,
    old_class_id: usize,
    new_class_id: usize,
    config: &MatchConfig,
) -> Vec<MemberMatch> {
    let index = FieldCandidateIndex::new(&new_class.fields);
    let mut results = Vec::new();
    for old_field in &old_class.fields {
        let candidates = index.candidates(old_field, member_candidate_scan_limit(config));
        let result = match_one_member_candidates(
            old_class_id,
            new_class_id,
            old_field.id,
            candidates.into_iter(),
            config,
            |new_field| score_field(old_field, new_field),
        );
        results.push(result);
    }
    push_unresolved_new_members(
        &mut results,
        old_class_id,
        new_class_id,
        new_class.fields.iter().map(|field| field.id),
        "no old field candidate above low-confidence threshold",
    );
    results
}

fn match_one_member_candidates<'a, T: 'a, F>(
    old_class_id: usize,
    new_class_id: usize,
    old_member_id: usize,
    new_members: impl Iterator<Item = &'a T>,
    config: &MatchConfig,
    score: F,
) -> MemberMatch
where
    F: Fn(&T) -> Candidate,
{
    let mut candidates = Vec::with_capacity(config.max_candidates);
    for candidate in new_members.map(score) {
        if candidate.score >= config.low_confidence {
            push_top_candidate(&mut candidates, candidate, config.max_candidates);
        }
    }
    sort_candidates(&mut candidates);

    let Some(best) = candidates.first().cloned() else {
        return MemberMatch {
            old_owner_class_id: Some(old_class_id),
            new_owner_class_id: Some(new_class_id),
            old_member_id: Some(old_member_id),
            new_member_id: None,
            score: 0.0,
            status: MatchStatus::UnresolvedOld,
            reasons: vec!["no new member candidate above low-confidence threshold".to_string()],
            candidates: Vec::new(),
        };
    };

    let status = if candidates
        .get(1)
        .is_some_and(|second| (best.score - second.score).abs() <= 0.03)
    {
        MatchStatus::Conflict
    } else if best.score >= config.min_confidence {
        MatchStatus::Matched
    } else {
        MatchStatus::LowConfidence
    };

    MemberMatch {
        old_owner_class_id: Some(old_class_id),
        new_owner_class_id: Some(new_class_id),
        old_member_id: Some(old_member_id),
        new_member_id: Some(best.entity_id),
        score: best.score,
        status,
        reasons: best.reasons.clone(),
        candidates,
    }
}

struct MethodCandidateIndex<'a> {
    all: &'a [MethodModel],
    by_name: BTreeMap<&'a str, Vec<&'a MethodModel>>,
    by_proto: BTreeMap<String, Vec<&'a MethodModel>>,
    by_string_ref: BTreeMap<&'a str, Vec<&'a MethodModel>>,
    by_method_ref: BTreeMap<&'a str, Vec<&'a MethodModel>>,
}

impl<'a> MethodCandidateIndex<'a> {
    fn new(methods: &'a [MethodModel]) -> Self {
        let mut by_name: BTreeMap<&'a str, Vec<&'a MethodModel>> = BTreeMap::new();
        let mut by_proto: BTreeMap<String, Vec<&'a MethodModel>> = BTreeMap::new();
        let mut by_string_ref: BTreeMap<&'a str, Vec<&'a MethodModel>> = BTreeMap::new();
        let mut by_method_ref: BTreeMap<&'a str, Vec<&'a MethodModel>> = BTreeMap::new();

        for method in methods {
            by_name.entry(&method.name).or_default().push(method);
            by_proto
                .entry(method_proto_key(method))
                .or_default()
                .push(method);
            if let Some(code) = &method.code {
                for item in code.string_refs.iter().take(32) {
                    by_string_ref.entry(item).or_default().push(method);
                }
                for item in code.method_refs.iter().take(32) {
                    by_method_ref.entry(item).or_default().push(method);
                }
            }
        }

        Self {
            all: methods,
            by_name,
            by_proto,
            by_string_ref,
            by_method_ref,
        }
    }

    fn candidates(&self, old: &MethodModel, limit: usize) -> Vec<&'a MethodModel> {
        let mut result = Vec::new();
        let mut seen = BTreeSet::new();
        self.extend_bucket(
            self.by_name.get(old.name.as_str()),
            &mut result,
            &mut seen,
            limit,
        );
        self.extend_bucket(
            self.by_proto.get(&method_proto_key(old)),
            &mut result,
            &mut seen,
            limit,
        );
        if let Some(code) = &old.code {
            for item in code.string_refs.iter().take(16) {
                self.extend_bucket(
                    self.by_string_ref.get(item.as_str()),
                    &mut result,
                    &mut seen,
                    limit,
                );
                if result.len() >= limit {
                    return result;
                }
            }
            for item in code.method_refs.iter().take(16) {
                self.extend_bucket(
                    self.by_method_ref.get(item.as_str()),
                    &mut result,
                    &mut seen,
                    limit,
                );
                if result.len() >= limit {
                    return result;
                }
            }
        }
        if result.is_empty() {
            for method in self.all.iter().take(limit) {
                result.push(method);
            }
        }
        result
    }

    fn extend_bucket(
        &self,
        bucket: Option<&Vec<&'a MethodModel>>,
        result: &mut Vec<&'a MethodModel>,
        seen: &mut BTreeSet<usize>,
        limit: usize,
    ) {
        let Some(bucket) = bucket else {
            return;
        };
        for method in bucket {
            if seen.insert(method.id) {
                result.push(*method);
                if result.len() >= limit {
                    return;
                }
            }
        }
    }
}

struct FieldCandidateIndex<'a> {
    all: &'a [FieldModel],
    by_name: BTreeMap<&'a str, Vec<&'a FieldModel>>,
    by_type: BTreeMap<&'a str, Vec<&'a FieldModel>>,
}

impl<'a> FieldCandidateIndex<'a> {
    fn new(fields: &'a [FieldModel]) -> Self {
        let mut by_name: BTreeMap<&'a str, Vec<&'a FieldModel>> = BTreeMap::new();
        let mut by_type: BTreeMap<&'a str, Vec<&'a FieldModel>> = BTreeMap::new();
        for field in fields {
            by_name.entry(&field.name).or_default().push(field);
            by_type.entry(&field.field_type).or_default().push(field);
        }
        Self {
            all: fields,
            by_name,
            by_type,
        }
    }

    fn candidates(&self, old: &FieldModel, limit: usize) -> Vec<&'a FieldModel> {
        let mut result = Vec::new();
        let mut seen = BTreeSet::new();
        self.extend_bucket(
            self.by_name.get(old.name.as_str()),
            &mut result,
            &mut seen,
            limit,
        );
        self.extend_bucket(
            self.by_type.get(old.field_type.as_str()),
            &mut result,
            &mut seen,
            limit,
        );
        if result.is_empty() {
            for field in self.all.iter().take(limit) {
                result.push(field);
            }
        }
        result
    }

    fn extend_bucket(
        &self,
        bucket: Option<&Vec<&'a FieldModel>>,
        result: &mut Vec<&'a FieldModel>,
        seen: &mut BTreeSet<usize>,
        limit: usize,
    ) {
        let Some(bucket) = bucket else {
            return;
        };
        for field in bucket {
            if seen.insert(field.id) {
                result.push(*field);
                if result.len() >= limit {
                    return;
                }
            }
        }
    }
}

fn method_proto_key(method: &MethodModel) -> String {
    format!("({})->{}", method.parameters.join(","), method.return_type)
}

fn member_candidate_scan_limit(config: &MatchConfig) -> usize {
    (config.max_candidates.max(1) * 32).max(128)
}

fn push_unresolved_new_members(
    results: &mut Vec<MemberMatch>,
    old_class_id: usize,
    new_class_id: usize,
    new_member_ids: impl Iterator<Item = usize>,
    reason: &str,
) {
    let matched_new: std::collections::BTreeSet<_> = results
        .iter()
        .filter(|item| {
            matches!(
                item.status,
                MatchStatus::Matched
                    | MatchStatus::LowConfidence
                    | MatchStatus::Conflict
                    | MatchStatus::SemanticBreak
            )
        })
        .filter_map(|item| item.new_member_id)
        .collect();

    for new_member_id in new_member_ids {
        if !matched_new.contains(&new_member_id) {
            results.push(MemberMatch {
                old_owner_class_id: Some(old_class_id),
                new_owner_class_id: Some(new_class_id),
                old_member_id: None,
                new_member_id: Some(new_member_id),
                score: 0.0,
                status: MatchStatus::UnresolvedNew,
                reasons: vec![reason.to_string()],
                candidates: Vec::new(),
            });
        }
    }
}

fn score_method(old: &MethodModel, new: &MethodModel) -> Candidate {
    let name_score = equal_score(&old.name, &new.name);
    let return_score = equal_score(&old.return_type, &new.return_type);
    let params_score = equal_score(&old.parameters, &new.parameters);
    let (score, code_reason) = match (&old.code, &new.code) {
        (Some(old_code), Some(new_code)) => {
            let code_score = score_method_code(old_code, new_code);
            (
                name_score * 0.20 + return_score * 0.20 + params_score * 0.20 + code_score * 0.40,
                Some(format!("bytecode score {:.2}", code_score)),
            )
        }
        _ => (
            name_score * 0.35 + return_score * 0.30 + params_score * 0.35,
            None,
        ),
    };
    let mut reasons = vec![
        format!("method name score {:.2}", name_score),
        format!(
            "prototype score {:.2}",
            return_score * 0.30 + params_score * 0.35
        ),
    ];
    if let Some(reason) = code_reason {
        reasons.push(reason);
    }
    Candidate {
        entity_id: new.id,
        score,
        reasons,
    }
}

fn score_method_code(
    old: &crate::model::MethodCodeSummary,
    new: &crate::model::MethodCodeSummary,
) -> f32 {
    let old_strings = old.string_refs.iter().cloned().collect();
    let new_strings = new.string_refs.iter().cloned().collect();
    let old_methods = old.method_refs.iter().cloned().collect();
    let new_methods = new.method_refs.iter().cloned().collect();
    let old_fields = old.field_refs.iter().cloned().collect();
    let new_fields = new.field_refs.iter().cloned().collect();
    let control_score = control_flow_score(old, new);

    histogram_cosine_u8(&old.opcode_histogram, &new.opcode_histogram) * 0.35
        + bounded_ratio(old.instruction_count, new.instruction_count) * 0.20
        + control_score * 0.20
        + signal_jaccard(&old_strings, &new_strings) * 0.10
        + signal_jaccard(&old_methods, &new_methods) * 0.10
        + signal_jaccard(&old_fields, &new_fields) * 0.05
}

fn control_flow_score(
    old: &crate::model::MethodCodeSummary,
    new: &crate::model::MethodCodeSummary,
) -> f32 {
    (bounded_ratio(old.branch_count, new.branch_count)
        + bounded_ratio(old.return_count, new.return_count)
        + bounded_ratio(old.throw_count, new.throw_count)
        + bounded_ratio(old.switch_count, new.switch_count))
        / 4.0
}

fn score_field(old: &FieldModel, new: &FieldModel) -> Candidate {
    let name_score = equal_score(&old.name, &new.name);
    let type_score = equal_score(&old.field_type, &new.field_type);
    let score = name_score * 0.40 + type_score * 0.60;
    Candidate {
        entity_id: new.id,
        score,
        reasons: vec![
            format!("field name score {:.2}", name_score),
            format!("field type score {:.2}", type_score),
        ],
    }
}

fn match_one_class(
    old_class: &ClassFingerprint,
    index: &ClassCandidateIndex<'_>,
    context: &MatchContext,
    config: &MatchConfig,
) -> ClassMatch {
    let exact_candidate = index
        .by_descriptor
        .get(old_class.descriptor.as_str())
        .map(|exact| score_class(old_class, exact, context));
    if let Some(candidate) = &exact_candidate {
        if candidate.score >= config.low_confidence && !is_unsafe_candidate(candidate) {
            return class_match_from_candidates(old_class, vec![candidate.clone()], config);
        }
    }

    let candidate_refs =
        index.compatible_candidates(old_class, context, candidate_scan_limit(config));
    let mut candidates =
        collect_class_candidates(old_class, candidate_refs.into_iter(), context, config);
    if let Some(candidate) = exact_candidate {
        if candidate.score >= config.low_confidence
            && !candidates
                .iter()
                .any(|existing| existing.entity_id == candidate.entity_id)
        {
            push_top_candidate(&mut candidates, candidate, config.max_candidates);
            sort_candidates(&mut candidates);
        }
    }
    if candidates.is_empty() {
        candidates = collect_class_candidates(
            old_class,
            index
                .fallback_candidates(candidate_scan_limit(config))
                .into_iter(),
            context,
            config,
        );
    }
    class_match_from_candidates(old_class, candidates, config)
}

fn class_match_from_candidates(
    old_class: &ClassFingerprint,
    candidates: Vec<Candidate>,
    config: &MatchConfig,
) -> ClassMatch {
    let Some(best) = candidates.first().cloned() else {
        return ClassMatch {
            old_class_id: Some(old_class.class_id),
            new_class_id: None,
            score: 0.0,
            status: MatchStatus::UnresolvedOld,
            reasons: vec!["no new candidate above low-confidence threshold".to_string()],
            candidates: Vec::new(),
        };
    };

    let best_verified = is_verified_candidate(&best);
    let status = if has_semantic_break(&best) {
        MatchStatus::SemanticBreak
    } else if has_unsafe_same_descriptor_weak_shape(&best)
        || candidates.get(1).is_some_and(|second| {
            (best.score - second.score).abs() <= 0.03
                && (!best_verified || is_verified_candidate(second))
        })
    {
        MatchStatus::Conflict
    } else if config.verified_only && !best_verified {
        MatchStatus::LowConfidence
    } else if best.score >= config.min_confidence {
        MatchStatus::Matched
    } else {
        MatchStatus::LowConfidence
    };

    ClassMatch {
        old_class_id: Some(old_class.class_id),
        new_class_id: Some(best.entity_id),
        score: best.score,
        status,
        reasons: best.reasons.clone(),
        candidates,
    }
}

#[derive(Debug, Clone)]
struct MatchContext {
    anchor_stats: AnchorStats,
}

impl MatchContext {
    fn new(old: &AppFingerprint, new: &AppFingerprint) -> Self {
        Self {
            anchor_stats: AnchorStats::build(old, new),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum AnchorKind {
    String,
    MethodRef,
    FieldRef,
    MethodProto,
    FieldType,
}

#[derive(Debug, Clone, Default)]
struct AnchorStats {
    old_counts: BTreeMap<(AnchorKind, String), usize>,
    new_counts: BTreeMap<(AnchorKind, String), usize>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct RareAnchorEvidence {
    string: usize,
    method_ref: usize,
    field_ref: usize,
    method_proto: usize,
    field_type: usize,
    total: usize,
    kind_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct GraphEvidence {
    matched_edges: usize,
    available_edges: usize,
    ratio: f32,
    score: f32,
}

impl AnchorStats {
    fn build(old: &AppFingerprint, new: &AppFingerprint) -> Self {
        Self {
            old_counts: count_anchor_frequencies(&old.classes),
            new_counts: count_anchor_frequencies(&new.classes),
        }
    }

    fn is_rare(&self, kind: AnchorKind, value: &str) -> bool {
        let key = (kind, value.to_string());
        let old_count = self.old_counts.get(&key).copied().unwrap_or(0);
        let new_count = self.new_counts.get(&key).copied().unwrap_or(0);
        old_count > 0
            && new_count > 0
            && old_count <= RARE_ANCHOR_MAX_FREQUENCY
            && new_count <= RARE_ANCHOR_MAX_FREQUENCY
    }

    fn rare_evidence(
        &self,
        old_class: &ClassFingerprint,
        new_class: &ClassFingerprint,
    ) -> RareAnchorEvidence {
        let string = rare_shared_count(
            self,
            AnchorKind::String,
            &old_class.strings,
            &new_class.strings,
        );
        let method_ref = rare_shared_count(
            self,
            AnchorKind::MethodRef,
            &old_class.method_ref_shapes,
            &new_class.method_ref_shapes,
        );
        let field_ref = rare_shared_count(
            self,
            AnchorKind::FieldRef,
            &old_class.field_ref_shapes,
            &new_class.field_ref_shapes,
        );
        let method_proto = rare_shared_count(
            self,
            AnchorKind::MethodProto,
            &old_class.method_proto_shapes,
            &new_class.method_proto_shapes,
        );
        let field_type = rare_shared_count(
            self,
            AnchorKind::FieldType,
            &old_class.field_type_shapes,
            &new_class.field_type_shapes,
        );
        let kind_count = [string, method_ref, field_ref, method_proto, field_type]
            .into_iter()
            .filter(|count| *count > 0)
            .count();

        RareAnchorEvidence {
            string,
            method_ref,
            field_ref,
            method_proto,
            field_type,
            total: string + method_ref + field_ref + method_proto + field_type,
            kind_count,
        }
    }
}

fn count_anchor_frequencies(classes: &[ClassFingerprint]) -> BTreeMap<(AnchorKind, String), usize> {
    let mut counts = BTreeMap::new();
    for class in classes {
        count_anchor_set(&mut counts, AnchorKind::String, &class.strings);
        count_anchor_set(&mut counts, AnchorKind::MethodRef, &class.method_ref_shapes);
        count_anchor_set(&mut counts, AnchorKind::FieldRef, &class.field_ref_shapes);
        count_anchor_set(
            &mut counts,
            AnchorKind::MethodProto,
            &class.method_proto_shapes,
        );
        count_anchor_set(&mut counts, AnchorKind::FieldType, &class.field_type_shapes);
    }
    counts
}

fn count_anchor_set(
    counts: &mut BTreeMap<(AnchorKind, String), usize>,
    kind: AnchorKind,
    values: &BTreeSet<String>,
) {
    for value in values {
        if is_useful_anchor(value) {
            *counts.entry((kind, value.clone())).or_insert(0) += 1;
        }
    }
}

fn rare_shared_count(
    stats: &AnchorStats,
    kind: AnchorKind,
    old_values: &BTreeSet<String>,
    new_values: &BTreeSet<String>,
) -> usize {
    old_values
        .intersection(new_values)
        .filter(|value| stats.is_rare(kind, value))
        .count()
}

struct ClassCandidateIndex<'a> {
    all: &'a [ClassFingerprint],
    by_descriptor: BTreeMap<&'a str, &'a ClassFingerprint>,
    by_counts: BTreeMap<(usize, usize), Vec<&'a ClassFingerprint>>,
    by_method_proto: BTreeMap<&'a str, Vec<&'a ClassFingerprint>>,
    by_string: BTreeMap<&'a str, Vec<&'a ClassFingerprint>>,
    by_method_ref: BTreeMap<&'a str, Vec<&'a ClassFingerprint>>,
    by_field_ref: BTreeMap<&'a str, Vec<&'a ClassFingerprint>>,
}

impl<'a> ClassCandidateIndex<'a> {
    fn new(classes: &'a [ClassFingerprint]) -> Self {
        let mut by_descriptor = BTreeMap::new();
        let mut by_counts: BTreeMap<(usize, usize), Vec<&'a ClassFingerprint>> = BTreeMap::new();
        let mut by_method_proto: BTreeMap<&'a str, Vec<&'a ClassFingerprint>> = BTreeMap::new();
        let mut by_string: BTreeMap<&'a str, Vec<&'a ClassFingerprint>> = BTreeMap::new();
        let mut by_method_ref: BTreeMap<&'a str, Vec<&'a ClassFingerprint>> = BTreeMap::new();
        let mut by_field_ref: BTreeMap<&'a str, Vec<&'a ClassFingerprint>> = BTreeMap::new();

        for class in classes {
            by_descriptor.insert(class.descriptor.as_str(), class);
            by_counts
                .entry((class.method_shapes.len(), class.field_shapes.len()))
                .or_default()
                .push(class);
            for item in &class.method_proto_shapes {
                by_method_proto.entry(item).or_default().push(class);
            }
            for item in &class.strings {
                if is_useful_anchor(item) {
                    by_string.entry(item).or_default().push(class);
                }
            }
            for item in &class.method_ref_shapes {
                by_method_ref.entry(item).or_default().push(class);
            }
            for item in &class.field_ref_shapes {
                by_field_ref.entry(item).or_default().push(class);
            }
        }

        Self {
            all: classes,
            by_descriptor,
            by_counts,
            by_method_proto,
            by_string,
            by_method_ref,
            by_field_ref,
        }
    }

    fn compatible_candidates(
        &self,
        old_class: &ClassFingerprint,
        context: &MatchContext,
        limit: usize,
    ) -> Vec<&'a ClassFingerprint> {
        let old_methods = old_class.method_shapes.len();
        let old_fields = old_class.field_shapes.len();
        let method_window = old_methods.max(4) / 2;
        let field_window = old_fields.max(4) / 2;
        let min_methods = old_methods.saturating_sub(method_window);
        let max_methods = old_methods.saturating_add(method_window);
        let min_fields = old_fields.saturating_sub(field_window);
        let max_fields = old_fields.saturating_add(field_window);
        let mut candidates = Vec::new();
        let mut seen = BTreeSet::new();

        self.extend_anchor_candidates(old_class, context, &mut candidates, &mut seen, limit);
        if candidates.len() >= limit {
            return candidates;
        }

        for ((_, fields), bucket) in self
            .by_counts
            .range((min_methods, 0)..=(max_methods, usize::MAX))
        {
            if *fields < min_fields || *fields > max_fields {
                continue;
            }
            for class in bucket
                .iter()
                .copied()
                .filter(|class| cheap_bucket_compatible(old_class, class))
            {
                if !seen.insert(class.class_id) {
                    continue;
                }
                candidates.push(class);
                if candidates.len() >= limit {
                    return candidates;
                }
            }
        }

        candidates
    }

    fn extend_anchor_candidates(
        &self,
        old_class: &ClassFingerprint,
        context: &MatchContext,
        candidates: &mut Vec<&'a ClassFingerprint>,
        seen: &mut BTreeSet<usize>,
        limit: usize,
    ) {
        let max_bucket = (limit * 4).clamp(512, 8192);

        self.extend_rare_anchor_candidates(
            old_class,
            candidates,
            seen,
            limit,
            &context.anchor_stats,
        );
        if candidates.len() >= limit {
            return;
        }

        for item in old_class
            .strings
            .iter()
            .filter(|item| is_useful_anchor(item))
            .take(32)
        {
            self.extend_anchor_bucket(
                self.by_string.get(item.as_str()),
                candidates,
                seen,
                limit,
                max_bucket,
            );
            if candidates.len() >= limit {
                return;
            }
        }

        for item in old_class.method_ref_shapes.iter().take(32) {
            self.extend_anchor_bucket(
                self.by_method_ref.get(item.as_str()),
                candidates,
                seen,
                limit,
                max_bucket,
            );
            if candidates.len() >= limit {
                return;
            }
        }

        for item in old_class.field_ref_shapes.iter().take(32) {
            self.extend_anchor_bucket(
                self.by_field_ref.get(item.as_str()),
                candidates,
                seen,
                limit,
                max_bucket,
            );
            if candidates.len() >= limit {
                return;
            }
        }

        for item in old_class.method_proto_shapes.iter().take(16) {
            self.extend_anchor_bucket(
                self.by_method_proto.get(item.as_str()),
                candidates,
                seen,
                limit,
                max_bucket,
            );
            if candidates.len() >= limit {
                return;
            }
        }
    }

    fn extend_rare_anchor_candidates(
        &self,
        old_class: &ClassFingerprint,
        candidates: &mut Vec<&'a ClassFingerprint>,
        seen: &mut BTreeSet<usize>,
        limit: usize,
        stats: &AnchorStats,
    ) {
        let max_bucket = (limit * 2).clamp(128, 2048);

        for item in old_class
            .strings
            .iter()
            .filter(|item| stats.is_rare(AnchorKind::String, item))
        {
            self.extend_anchor_bucket(
                self.by_string.get(item.as_str()),
                candidates,
                seen,
                limit,
                max_bucket,
            );
            if candidates.len() >= limit {
                return;
            }
        }

        for item in old_class
            .method_ref_shapes
            .iter()
            .filter(|item| stats.is_rare(AnchorKind::MethodRef, item))
        {
            self.extend_anchor_bucket(
                self.by_method_ref.get(item.as_str()),
                candidates,
                seen,
                limit,
                max_bucket,
            );
            if candidates.len() >= limit {
                return;
            }
        }

        for item in old_class
            .field_ref_shapes
            .iter()
            .filter(|item| stats.is_rare(AnchorKind::FieldRef, item))
        {
            self.extend_anchor_bucket(
                self.by_field_ref.get(item.as_str()),
                candidates,
                seen,
                limit,
                max_bucket,
            );
            if candidates.len() >= limit {
                return;
            }
        }

        for item in old_class
            .method_proto_shapes
            .iter()
            .filter(|item| stats.is_rare(AnchorKind::MethodProto, item))
        {
            self.extend_anchor_bucket(
                self.by_method_proto.get(item.as_str()),
                candidates,
                seen,
                limit,
                max_bucket,
            );
            if candidates.len() >= limit {
                return;
            }
        }
    }

    fn extend_anchor_bucket(
        &self,
        bucket: Option<&Vec<&'a ClassFingerprint>>,
        candidates: &mut Vec<&'a ClassFingerprint>,
        seen: &mut BTreeSet<usize>,
        limit: usize,
        max_bucket: usize,
    ) {
        let Some(bucket) = bucket else {
            return;
        };
        if bucket.len() > max_bucket {
            return;
        }
        for class in bucket {
            if seen.insert(class.class_id) {
                candidates.push(*class);
                if candidates.len() >= limit {
                    return;
                }
            }
        }
    }

    fn fallback_candidates(&self, limit: usize) -> Vec<&'a ClassFingerprint> {
        self.all.iter().take(limit).collect()
    }
}

fn is_useful_anchor(value: &str) -> bool {
    value.len() >= 4 && !value.chars().all(|ch| ch.is_ascii_digit())
}

fn candidate_scan_limit(config: &MatchConfig) -> usize {
    (config.max_candidates.max(1) * 512).max(4096)
}

fn collect_class_candidates<'a>(
    old_class: &ClassFingerprint,
    new_classes: impl Iterator<Item = &'a ClassFingerprint>,
    context: &MatchContext,
    config: &MatchConfig,
) -> Vec<Candidate> {
    let mut candidates = Vec::with_capacity(config.max_candidates);
    for candidate in new_classes.map(|new_class| score_class(old_class, new_class, context)) {
        if candidate.score >= config.low_confidence {
            push_top_candidate(&mut candidates, candidate, config.max_candidates);
        }
    }
    sort_candidates(&mut candidates);
    candidates
}

fn push_top_candidate(candidates: &mut Vec<Candidate>, candidate: Candidate, limit: usize) {
    if limit == 0 {
        return;
    }
    if candidates.len() < limit {
        candidates.push(candidate);
        return;
    }

    let Some((worst_index, worst)) = candidates
        .iter()
        .enumerate()
        .min_by(|(_, left), (_, right)| compare_candidates(left, right))
    else {
        return;
    };
    if compare_candidates(&candidate, worst).is_gt() {
        candidates[worst_index] = candidate;
    }
}

fn sort_candidates(candidates: &mut [Candidate]) {
    candidates.sort_by(|left, right| {
        right
            .score
            .total_cmp(&left.score)
            .then(left.entity_id.cmp(&right.entity_id))
    });
}

fn compare_candidates(left: &Candidate, right: &Candidate) -> std::cmp::Ordering {
    left.score
        .total_cmp(&right.score)
        .then_with(|| right.entity_id.cmp(&left.entity_id))
}

fn cheap_bucket_compatible(old_class: &ClassFingerprint, new_class: &ClassFingerprint) -> bool {
    let old_methods = old_class.method_shapes.len() as isize;
    let new_methods = new_class.method_shapes.len() as isize;
    let old_fields = old_class.field_shapes.len() as isize;
    let new_fields = new_class.field_shapes.len() as isize;
    (old_methods - new_methods).abs() <= old_methods.max(4) / 2
        && (old_fields - new_fields).abs() <= old_fields.max(4) / 2
}

fn propagate_scores(matches: &mut [ClassMatch]) {
    matches.sort_by_key(|item| {
        (
            item.old_class_id.unwrap_or(usize::MAX),
            item.new_class_id.unwrap_or(usize::MAX),
        )
    });
}

fn run_call_graph_verification(
    matches: &mut [ClassMatch],
    old: &AppFingerprint,
    new: &AppFingerprint,
    config: &MatchConfig,
) {
    let old_by_id = fingerprints_by_id(&old.classes);
    let new_by_id = fingerprints_by_id(&new.classes);

    for _pass in 0..CALL_GRAPH_VERIFY_PASSES {
        let verified_descriptor_map = verified_descriptor_map(matches, &old_by_id, &new_by_id);
        let mut promoted = 0usize;

        for item in matches.iter_mut() {
            if is_verified_class_match(item)
                || matches!(
                    item.status,
                    MatchStatus::Conflict | MatchStatus::SemanticBreak
                )
            {
                continue;
            }
            let Some(old_class) = item
                .old_class_id
                .and_then(|id| old_by_id.get(id).copied().flatten())
            else {
                continue;
            };
            let Some(new_class) = item
                .new_class_id
                .and_then(|id| new_by_id.get(id).copied().flatten())
            else {
                continue;
            };
            if !graph_shape_compatible(old_class, new_class) {
                continue;
            }
            let Some(evidence) = graph_evidence(old_class, new_class, &verified_descriptor_map)
            else {
                continue;
            };
            if graph_candidate_is_ambiguous(
                item,
                &new_by_id,
                old_class,
                &verified_descriptor_map,
                evidence,
            ) {
                continue;
            }

            item.score = item.score.max(evidence.score);
            item.status = if config.verified_only || item.score >= config.min_confidence {
                MatchStatus::Matched
            } else {
                MatchStatus::LowConfidence
            };
            item.reasons
                .push(VERIFIED_CALL_GRAPH_NEIGHBORHOOD.to_string());
            item.reasons.push(format!(
                "call graph verified edges: {}/{}",
                evidence.matched_edges, evidence.available_edges
            ));
            promoted += 1;
        }

        if promoted == 0 {
            break;
        }
    }
}

fn verified_descriptor_map(
    matches: &[ClassMatch],
    old_by_id: &[Option<&ClassFingerprint>],
    new_by_id: &[Option<&ClassFingerprint>],
) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for item in matches {
        if !is_verified_class_match(item) {
            continue;
        }
        let Some(old_class) = item
            .old_class_id
            .and_then(|id| old_by_id.get(id).copied().flatten())
        else {
            continue;
        };
        let Some(new_class) = item
            .new_class_id
            .and_then(|id| new_by_id.get(id).copied().flatten())
        else {
            continue;
        };
        map.insert(old_class.descriptor.clone(), new_class.descriptor.clone());
    }
    map
}

fn is_verified_class_match(item: &ClassMatch) -> bool {
    item.status == MatchStatus::Matched
        && item
            .reasons
            .iter()
            .any(|reason| reason.starts_with("verified:"))
}

fn graph_evidence(
    old_class: &ClassFingerprint,
    new_class: &ClassFingerprint,
    verified_descriptor_map: &BTreeMap<String, String>,
) -> Option<GraphEvidence> {
    let expected_new_refs: BTreeSet<_> = old_class
        .class_ref_shapes
        .iter()
        .filter_map(|old_ref| verified_descriptor_map.get(old_ref))
        .cloned()
        .collect();

    let available_edges = expected_new_refs.len();
    if available_edges < 2 {
        return None;
    }

    let matched_edges = expected_new_refs
        .iter()
        .filter(|expected| new_class.class_ref_shapes.contains(*expected))
        .count();
    let ratio = matched_edges as f32 / available_edges as f32;
    if matched_edges < 2 || ratio < 0.60 {
        return None;
    }

    let score = if ratio >= 0.90 && matched_edges >= 3 {
        0.94
    } else if ratio >= 0.75 {
        0.92
    } else {
        0.90
    };

    Some(GraphEvidence {
        matched_edges,
        available_edges,
        ratio,
        score,
    })
}

fn graph_shape_compatible(old_class: &ClassFingerprint, new_class: &ClassFingerprint) -> bool {
    let method_proto_score = jaccard(
        &old_class.method_proto_shapes,
        &new_class.method_proto_shapes,
    );
    let field_type_score = jaccard(&old_class.field_type_shapes, &new_class.field_type_shapes);
    let instruction_score = if old_class.instruction_count == 0 && new_class.instruction_count == 0
    {
        1.0
    } else {
        bounded_ratio(old_class.instruction_count, new_class.instruction_count)
    };
    let opcode_score =
        if old_class.opcode_histogram.is_empty() && new_class.opcode_histogram.is_empty() {
            1.0
        } else {
            histogram_cosine_u8(&old_class.opcode_histogram, &new_class.opcode_histogram)
        };

    method_proto_score >= 0.60
        && field_type_score >= 0.50
        && instruction_score >= 0.50
        && opcode_score >= 0.60
}

fn graph_candidate_is_ambiguous(
    item: &ClassMatch,
    new_by_id: &[Option<&ClassFingerprint>],
    old_class: &ClassFingerprint,
    verified_descriptor_map: &BTreeMap<String, String>,
    best_evidence: GraphEvidence,
) -> bool {
    item.candidates.iter().skip(1).any(|candidate| {
        let Some(other_class) = new_by_id.get(candidate.entity_id).copied().flatten() else {
            return false;
        };
        let Some(other_evidence) = graph_evidence(old_class, other_class, verified_descriptor_map)
        else {
            return false;
        };
        other_evidence.matched_edges >= best_evidence.matched_edges
            && (other_evidence.ratio - best_evidence.ratio).abs() <= 0.10
    })
}

fn score_class(
    old_class: &ClassFingerprint,
    new_class: &ClassFingerprint,
    context: &MatchContext,
) -> Candidate {
    let descriptor_score = if old_class.descriptor == new_class.descriptor {
        1.0
    } else {
        0.0
    };
    let superclass_score = exact_option(&old_class.superclass, &new_class.superclass);
    let interface_score = jaccard(&old_class.interfaces, &new_class.interfaces);
    let method_score = jaccard(&old_class.method_shapes, &new_class.method_shapes);
    let field_score = jaccard(&old_class.field_shapes, &new_class.field_shapes);
    let method_proto_score = jaccard(
        &old_class.method_proto_shapes,
        &new_class.method_proto_shapes,
    );
    let field_type_score = jaccard(&old_class.field_type_shapes, &new_class.field_type_shapes);
    let package_score = if old_class.package_shape == new_class.package_shape {
        1.0
    } else {
        0.0
    };
    let string_score = signal_jaccard(&old_class.strings, &new_class.strings);
    let method_ref_score =
        signal_jaccard(&old_class.method_ref_shapes, &new_class.method_ref_shapes);
    let field_ref_score = signal_jaccard(&old_class.field_ref_shapes, &new_class.field_ref_shapes);
    let instruction_score = if old_class.instruction_count == 0 && new_class.instruction_count == 0
    {
        0.0
    } else {
        bounded_ratio(old_class.instruction_count, new_class.instruction_count)
    };
    let opcode_score =
        histogram_cosine_u8(&old_class.opcode_histogram, &new_class.opcode_histogram);

    let mut score = descriptor_score * 0.15
        + superclass_score * 0.10
        + interface_score * 0.06
        + method_score * 0.16
        + field_score * 0.10
        + method_proto_score * 0.14
        + field_type_score * 0.08
        + package_score * 0.03
        + string_score * 0.08
        + method_ref_score * 0.05
        + field_ref_score * 0.03
        + instruction_score * 0.01
        + opcode_score * 0.01;

    let verified = class_pattern_verification(
        old_class,
        new_class,
        ClassSimilarity {
            superclass_score,
            interface_score,
            method_score,
            field_score,
            method_proto_score,
            field_type_score,
            string_score,
            method_ref_score,
            field_ref_score,
            instruction_score,
            opcode_score,
        },
        context,
    );
    let mut reasons = Vec::new();
    if class_kind_changed(old_class, new_class) {
        reasons.push(SEMANTIC_BREAK_CLASS_KIND.to_string());
    }
    if let Some(verification) = &verified {
        score = score.max(verification.score);
        reasons.push(verification.reason.clone());
        if verification.reason == VERIFIED_RARE_ANCHORS_STABLE_SHAPE {
            let evidence = context.anchor_stats.rare_evidence(old_class, new_class);
            reasons.push(format!(
                "rare anchors: string={} method_ref={} field_ref={} method_proto={} field_type={}",
                evidence.string,
                evidence.method_ref,
                evidence.field_ref,
                evidence.method_proto,
                evidence.field_type
            ));
        }
    }
    if descriptor_score == 1.0 {
        reasons.push("same descriptor".to_string());
        if same_descriptor_weak_shape(old_class, new_class, method_score) {
            reasons.push(UNSAFE_SAME_DESCRIPTOR_WEAK_SHAPE.to_string());
        }
        if verified.is_none() && score < 0.82 {
            score = 0.82;
            reasons.push("exact descriptor confidence floor".to_string());
        }
    }
    if superclass_score == 1.0 {
        reasons.push("same superclass".to_string());
    }
    if method_score > 0.0 {
        reasons.push(format!("method shape overlap {:.2}", method_score));
    }
    if field_score > 0.0 {
        reasons.push(format!("field shape overlap {:.2}", field_score));
    }
    if method_proto_score > 0.0 {
        reasons.push(format!("method proto overlap {:.2}", method_proto_score));
    }
    if field_type_score > 0.0 {
        reasons.push(format!("field type overlap {:.2}", field_type_score));
    }
    if string_score > 0.0 && (!old_class.strings.is_empty() || !new_class.strings.is_empty()) {
        reasons.push(format!("string overlap {:.2}", string_score));
    }
    if method_ref_score > 0.0
        && (!old_class.method_ref_shapes.is_empty() || !new_class.method_ref_shapes.is_empty())
    {
        reasons.push(format!("method ref overlap {:.2}", method_ref_score));
    }
    if field_ref_score > 0.0
        && (!old_class.field_ref_shapes.is_empty() || !new_class.field_ref_shapes.is_empty())
    {
        reasons.push(format!("field ref overlap {:.2}", field_ref_score));
    }
    if opcode_score > 0.0 {
        reasons.push(format!("opcode shape overlap {:.2}", opcode_score));
    }

    Candidate {
        entity_id: new_class.class_id,
        score,
        reasons,
    }
}

#[derive(Debug, Clone, Copy)]
struct ClassSimilarity {
    superclass_score: f32,
    interface_score: f32,
    method_score: f32,
    field_score: f32,
    method_proto_score: f32,
    field_type_score: f32,
    string_score: f32,
    method_ref_score: f32,
    field_ref_score: f32,
    instruction_score: f32,
    opcode_score: f32,
}

#[derive(Debug, Clone)]
struct ClassVerification {
    reason: String,
    score: f32,
}

fn is_verified_candidate(candidate: &Candidate) -> bool {
    candidate
        .reasons
        .iter()
        .any(|reason| reason.starts_with("verified:"))
}

fn is_unsafe_candidate(candidate: &Candidate) -> bool {
    has_semantic_break(candidate) || has_unsafe_same_descriptor_weak_shape(candidate)
}

fn has_semantic_break(candidate: &Candidate) -> bool {
    candidate
        .reasons
        .iter()
        .any(|reason| reason == SEMANTIC_BREAK_CLASS_KIND)
}

fn has_unsafe_same_descriptor_weak_shape(candidate: &Candidate) -> bool {
    candidate
        .reasons
        .iter()
        .any(|reason| reason == UNSAFE_SAME_DESCRIPTOR_WEAK_SHAPE)
}

fn class_kind_changed(old: &ClassFingerprint, new: &ClassFingerprint) -> bool {
    (old.access_flags & ACC_INTERFACE != 0) != (new.access_flags & ACC_INTERFACE != 0)
}

fn same_descriptor_weak_shape(
    old: &ClassFingerprint,
    new: &ClassFingerprint,
    method_score: f32,
) -> bool {
    old.descriptor == new.descriptor
        && old.method_shapes.len().min(new.method_shapes.len()) >= 3
        && method_score < 0.30
}

fn class_pattern_verification(
    old: &ClassFingerprint,
    new: &ClassFingerprint,
    similarity: ClassSimilarity,
    context: &MatchContext,
) -> Option<ClassVerification> {
    if exact_class_fingerprint_match(old, new) {
        return Some(ClassVerification {
            reason: VERIFIED_EXACT_CLASS_FINGERPRINT.to_string(),
            score: 1.0,
        });
    }

    if exact_descriptor_stable_api_match(old, new) {
        return Some(ClassVerification {
            reason: VERIFIED_EXACT_DESCRIPTOR_STABLE_API.to_string(),
            score: 0.96,
        });
    }

    if exact_descriptor_stable_code_match(old, new, similarity) {
        return Some(ClassVerification {
            reason: VERIFIED_EXACT_DESCRIPTOR_STABLE_CODE.to_string(),
            score: 0.94,
        });
    }

    if exact_descriptor_stable_proto_code_match(old, new, similarity) {
        return Some(ClassVerification {
            reason: VERIFIED_EXACT_DESCRIPTOR_STABLE_PROTO_CODE.to_string(),
            score: 0.92,
        });
    }

    if renamed_exact_behavior_match(old, new) {
        return Some(ClassVerification {
            reason: VERIFIED_RENAMED_EXACT_BEHAVIOR.to_string(),
            score: 0.93,
        });
    }

    if renamed_stable_proto_anchor_match(old, new, similarity) {
        return Some(ClassVerification {
            reason: VERIFIED_RENAMED_STABLE_PROTO_ANCHOR.to_string(),
            score: 0.90,
        });
    }

    if let Some(verification) = rare_anchor_stable_shape_match(old, new, similarity, context) {
        return Some(verification);
    }

    None
}

fn rare_anchor_stable_shape_match(
    old: &ClassFingerprint,
    new: &ClassFingerprint,
    similarity: ClassSimilarity,
    context: &MatchContext,
) -> Option<ClassVerification> {
    let evidence = context.anchor_stats.rare_evidence(old, new);
    let enough_rare_signal = evidence.kind_count >= 2 || evidence.total >= 3;
    if !enough_rare_signal {
        return None;
    }
    if !rare_anchor_shape_compatible(old, similarity) {
        return None;
    }

    let score = if evidence.kind_count >= 3 || evidence.total >= 4 {
        0.95
    } else if evidence.total >= 3 {
        0.93
    } else {
        0.91
    };

    Some(ClassVerification {
        reason: VERIFIED_RARE_ANCHORS_STABLE_SHAPE.to_string(),
        score,
    })
}

fn rare_anchor_shape_compatible(class: &ClassFingerprint, similarity: ClassSimilarity) -> bool {
    let proto_ok = class.method_proto_shapes.is_empty() || similarity.method_proto_score >= 0.70;
    let field_type_ok = class.field_type_shapes.is_empty() || similarity.field_type_score >= 0.60;
    let instruction_ok = class.instruction_count == 0 || similarity.instruction_score >= 0.60;
    let opcode_ok = class.opcode_histogram.is_empty() || similarity.opcode_score >= 0.70;
    proto_ok && field_type_ok && instruction_ok && opcode_ok
}

fn exact_class_fingerprint_match(old: &ClassFingerprint, new: &ClassFingerprint) -> bool {
    old.descriptor == new.descriptor
        && old.package_shape == new.package_shape
        && old.superclass == new.superclass
        && old.interfaces == new.interfaces
        && old.access_flags == new.access_flags
        && old.method_shapes == new.method_shapes
        && old.method_proto_shapes == new.method_proto_shapes
        && old.field_shapes == new.field_shapes
        && old.field_type_shapes == new.field_type_shapes
        && old.strings == new.strings
        && old.method_ref_shapes == new.method_ref_shapes
        && old.field_ref_shapes == new.field_ref_shapes
        && old.class_ref_shapes == new.class_ref_shapes
        && old.instruction_count == new.instruction_count
        && old.opcode_histogram == new.opcode_histogram
}

fn exact_descriptor_stable_api_match(old: &ClassFingerprint, new: &ClassFingerprint) -> bool {
    old.descriptor == new.descriptor
        && old.superclass == new.superclass
        && old.interfaces == new.interfaces
        && old.access_flags == new.access_flags
        && old.method_shapes == new.method_shapes
        && old.field_shapes == new.field_shapes
        && old.method_proto_shapes == new.method_proto_shapes
        && old.field_type_shapes == new.field_type_shapes
        && has_substantial_class_signal(old)
}

fn exact_descriptor_stable_code_match(
    old: &ClassFingerprint,
    new: &ClassFingerprint,
    similarity: ClassSimilarity,
) -> bool {
    old.descriptor == new.descriptor
        && old.access_flags == new.access_flags
        && similarity.superclass_score >= 0.99
        && similarity.interface_score >= 0.95
        && similarity.method_score >= 0.90
        && similarity.field_score >= 0.90
        && similarity.instruction_score >= 0.95
        && similarity.opcode_score >= 0.98
        && sparse_signal_score_ok(old, similarity)
        && has_substantial_class_signal(old)
}

fn exact_descriptor_stable_proto_code_match(
    old: &ClassFingerprint,
    new: &ClassFingerprint,
    similarity: ClassSimilarity,
) -> bool {
    old.descriptor == new.descriptor
        && old.access_flags == new.access_flags
        && similarity.superclass_score >= 0.99
        && similarity.interface_score >= 0.95
        && similarity.method_proto_score >= 0.95
        && similarity.field_type_score >= 0.95
        && similarity.instruction_score >= 0.92
        && similarity.opcode_score >= 0.96
        && strong_shared_anchor_score(old, similarity)
        && has_substantial_class_signal(old)
}

fn renamed_exact_behavior_match(old: &ClassFingerprint, new: &ClassFingerprint) -> bool {
    old.descriptor != new.descriptor
        && old.access_flags == new.access_flags
        && old.method_shapes == new.method_shapes
        && old.method_proto_shapes == new.method_proto_shapes
        && old.field_shapes == new.field_shapes
        && old.field_type_shapes == new.field_type_shapes
        && old.strings == new.strings
        && old.method_ref_shapes == new.method_ref_shapes
        && old.field_ref_shapes == new.field_ref_shapes
        && old.instruction_count == new.instruction_count
        && old.opcode_histogram == new.opcode_histogram
        && has_substantial_class_signal(old)
}

fn renamed_stable_proto_anchor_match(
    old: &ClassFingerprint,
    new: &ClassFingerprint,
    similarity: ClassSimilarity,
) -> bool {
    old.descriptor != new.descriptor
        && old.access_flags == new.access_flags
        && similarity.method_proto_score >= 0.98
        && similarity.field_type_score >= 0.98
        && similarity.instruction_score >= 0.95
        && similarity.opcode_score >= 0.98
        && strong_shared_anchor_score(old, similarity)
        && has_substantial_class_signal(old)
}

fn has_substantial_class_signal(class: &ClassFingerprint) -> bool {
    class.method_shapes.len() + class.field_shapes.len() >= 2
        || class.method_proto_shapes.len() + class.field_type_shapes.len() >= 3
        || class.instruction_count >= 20
        || class.strings.len() + class.method_ref_shapes.len() + class.field_ref_shapes.len() >= 2
}

fn sparse_signal_score_ok(class: &ClassFingerprint, similarity: ClassSimilarity) -> bool {
    let has_strings = !class.strings.is_empty();
    let has_method_refs = !class.method_ref_shapes.is_empty();
    let has_field_refs = !class.field_ref_shapes.is_empty();

    (!has_strings || similarity.string_score >= 0.70)
        && (!has_method_refs || similarity.method_ref_score >= 0.70)
        && (!has_field_refs || similarity.field_ref_score >= 0.70)
}

fn strong_shared_anchor_score(class: &ClassFingerprint, similarity: ClassSimilarity) -> bool {
    let string_weight = if class.strings.is_empty() {
        0.0
    } else {
        similarity.string_score
    };
    let method_ref_weight = if class.method_ref_shapes.is_empty() {
        0.0
    } else {
        similarity.method_ref_score
    };
    let field_ref_weight = if class.field_ref_shapes.is_empty() {
        0.0
    } else {
        similarity.field_ref_score
    };

    string_weight >= 0.80
        || method_ref_weight >= 0.80
        || field_ref_weight >= 0.80
        || string_weight + method_ref_weight + field_ref_weight >= 1.35
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use crate::fingerprint::{AppFingerprint, ClassFingerprint};

    use crate::fingerprint::fingerprint_app;
    use crate::model::{
        AppModel, ClassModel, DexOrigin, FieldModel, MethodCodeSummary, MethodModel, ParseCoverage,
    };

    use super::{
        match_app_models, match_classes, AnchorKind, AnchorStats, MatchConfig, MatchStatus,
        VERIFIED_CALL_GRAPH_NEIGHBORHOOD, VERIFIED_RARE_ANCHORS_STABLE_SHAPE,
    };

    fn fp(id: usize, descriptor: &str, methods: &[&str]) -> ClassFingerprint {
        ClassFingerprint {
            class_id: id,
            descriptor: descriptor.to_string(),
            package_shape: "*.*".to_string(),
            superclass: Some("Ljava/lang/Object;".to_string()),
            interfaces: BTreeSet::new(),
            access_flags: 1,
            method_shapes: methods.iter().map(|item| item.to_string()).collect(),
            method_proto_shapes: methods
                .iter()
                .map(|item| {
                    item.split_once('(')
                        .map(|(_, proto)| format!("({proto}"))
                        .unwrap_or_else(|| item.to_string())
                })
                .collect(),
            field_shapes: BTreeSet::new(),
            field_type_shapes: BTreeSet::new(),
            strings: BTreeSet::new(),
            method_ref_shapes: BTreeSet::new(),
            field_ref_shapes: BTreeSet::new(),
            class_ref_shapes: BTreeSet::new(),
            instruction_count: 0,
            opcode_histogram: BTreeMap::new(),
        }
    }

    #[test]
    fn matches_renamed_class_by_structure() {
        let old = AppFingerprint {
            classes: vec![fp(1, "La/b/C;", &["a()->V", "b(I)->I"])],
        };
        let new = AppFingerprint {
            classes: vec![fp(2, "Lx/y/Z;", &["a()->V", "b(I)->I"])],
        };
        let result = match_classes(
            &old,
            &new,
            &MatchConfig {
                min_confidence: 0.70,
                low_confidence: 0.50,
                max_candidates: 10,
                verified_only: false,
            },
        );
        assert_eq!(result[0].status, MatchStatus::Matched);
        assert_eq!(result[0].old_class_id, Some(1));
        assert_eq!(result[0].new_class_id, Some(2));
    }

    #[test]
    fn class_matcher_reports_unresolved_new_classes() {
        let old = AppFingerprint {
            classes: Vec::new(),
        };
        let new = AppFingerprint {
            classes: vec![fp(7, "Lx/New;", &["a()->V"])],
        };
        let result = match_classes(
            &old,
            &new,
            &MatchConfig {
                min_confidence: 0.80,
                low_confidence: 0.55,
                max_candidates: 10,
                verified_only: false,
            },
        );
        assert_eq!(result[0].status, MatchStatus::UnresolvedNew);
        assert_eq!(result[0].new_class_id, Some(7));
    }

    #[test]
    fn shared_new_class_is_a_conflict_even_in_verified_only_mode() {
        let old = AppFingerprint {
            classes: vec![
                fp(1, "La/A;", &["first()->V", "second(I)->I"]),
                fp(2, "La/B;", &["first()->V", "second(I)->I"]),
            ],
        };
        let new = AppFingerprint {
            classes: vec![fp(3, "La/C;", &["first()->V", "second(I)->I"])],
        };
        for verified_only in [false, true] {
            let result = match_classes(
                &old,
                &new,
                &MatchConfig {
                    min_confidence: 0.80,
                    low_confidence: 0.55,
                    max_candidates: 10,
                    verified_only,
                },
            );
            assert_eq!(result.len(), 2);
            for item in result {
                assert_eq!(item.new_class_id, Some(3));
                assert_eq!(item.status, MatchStatus::Conflict);
                assert!(item
                    .reasons
                    .iter()
                    .any(|reason| reason == super::CONFLICT_SHARED_NEW_CLASS));
                assert!(!item
                    .reasons
                    .iter()
                    .any(|reason| reason.starts_with("verified:")));
            }
        }
    }

    #[test]
    fn low_memory_matching_rejects_duplicate_old_descriptors() {
        let old = AppFingerprint {
            classes: vec![fp(1, "La/A;", &[]), fp(2, "La/A;", &[])],
        };
        let new = AppFingerprint {
            classes: vec![fp(3, "La/A;", &[])],
        };
        let report = super::match_apps_low_memory(
            &old,
            &new,
            &MatchConfig {
                min_confidence: 0.80,
                low_confidence: 0.55,
                max_candidates: 10,
                verified_only: true,
            },
        );
        assert_eq!(report.classes.len(), 2);
        assert!(report
            .classes
            .iter()
            .all(|item| item.status == MatchStatus::Conflict));
    }

    #[test]
    fn exact_descriptor_matches_sparse_classes() {
        let old = AppFingerprint {
            classes: vec![fp(1, "La/Sparse;", &["a()->V"])],
        };
        let new = AppFingerprint {
            classes: vec![fp(2, "La/Sparse;", &[])],
        };
        let result = match_classes(
            &old,
            &new,
            &MatchConfig {
                min_confidence: 0.80,
                low_confidence: 0.55,
                max_candidates: 10,
                verified_only: false,
            },
        );
        assert_eq!(result[0].status, MatchStatus::Matched);
        assert_eq!(result[0].score, 0.82);
        assert!(result[0]
            .reasons
            .iter()
            .any(|reason| reason == "exact descriptor confidence floor"));
    }

    #[test]
    fn interface_to_class_same_descriptor_is_semantic_break() {
        let mut old_class = fp(1, "LX/0hp4;", &["a()->V", "b()->I", "c(I)->V"]);
        old_class.access_flags |= 0x0200;
        let new_class = fp(2, "LX/0hp4;", &["a()->V", "b()->I", "c(I)->V"]);

        let result = match_classes(
            &AppFingerprint {
                classes: vec![old_class],
            },
            &AppFingerprint {
                classes: vec![new_class],
            },
            &MatchConfig {
                min_confidence: 0.80,
                low_confidence: 0.55,
                max_candidates: 10,
                verified_only: false,
            },
        );

        assert_eq!(result[0].status, MatchStatus::SemanticBreak);
        assert!(result[0]
            .reasons
            .iter()
            .any(|reason| reason == "semantic break: class/interface access flag changed"));
    }

    #[test]
    fn weak_same_descriptor_does_not_hide_verified_renamed_candidate() {
        let old_class = fp(
            1,
            "LX/0gUi;",
            &["a(I)->V", "b()->I", "c(Ljava/lang/String;)->V"],
        );
        let same_name_different_class = fp(2, "LX/0gUi;", &["x()->V", "y(I)->I", "z(J)->Z"]);
        let renamed_same_class = fp(
            3,
            "LX/0d2t;",
            &["a(I)->V", "b()->I", "c(Ljava/lang/String;)->V"],
        );

        let result = match_classes(
            &AppFingerprint {
                classes: vec![old_class],
            },
            &AppFingerprint {
                classes: vec![same_name_different_class, renamed_same_class],
            },
            &MatchConfig {
                min_confidence: 0.80,
                low_confidence: 0.55,
                max_candidates: 10,
                verified_only: false,
            },
        );

        assert_eq!(result[0].status, MatchStatus::Matched);
        assert_eq!(result[0].new_class_id, Some(3));
        assert!(result[0]
            .reasons
            .iter()
            .any(|reason| reason == "verified: renamed exact behavior pattern"));
    }

    #[test]
    fn verified_only_requires_exact_class_fingerprint() {
        let old = AppFingerprint {
            classes: vec![fp(1, "La/Sparse;", &["a()->V"])],
        };
        let new = AppFingerprint {
            classes: vec![fp(2, "La/Sparse;", &[])],
        };
        let result = match_classes(
            &old,
            &new,
            &MatchConfig {
                min_confidence: 0.80,
                low_confidence: 0.55,
                max_candidates: 10,
                verified_only: true,
            },
        );
        assert_eq!(result[0].status, MatchStatus::LowConfidence);
        assert_eq!(result[0].score, 0.82);
    }

    #[test]
    fn verified_only_accepts_stable_api_pattern() {
        let mut old_class = fp(1, "La/Stable;", &["a()->V", "b(I)->I"]);
        old_class.strings.insert("old label".to_string());
        let mut new_class = fp(2, "La/Stable;", &["a()->V", "b(I)->I"]);
        new_class.strings.insert("new label".to_string());
        let old = AppFingerprint {
            classes: vec![old_class],
        };
        let new = AppFingerprint {
            classes: vec![new_class],
        };
        let result = match_classes(
            &old,
            &new,
            &MatchConfig {
                min_confidence: 0.80,
                low_confidence: 0.55,
                max_candidates: 10,
                verified_only: true,
            },
        );
        assert_eq!(result[0].status, MatchStatus::Matched);
        assert!(result[0]
            .reasons
            .iter()
            .any(|reason| reason == "verified: exact descriptor and stable API shape"));
    }

    #[test]
    fn anchor_stats_mark_values_rare_only_when_rare_in_both_apps() {
        let mut old_rare = fp(1, "Lo/Rare;", &["a()->V"]);
        old_rare.strings.insert("rare-login-token".to_string());
        let mut new_rare = fp(2, "Ln/Rare;", &["a()->V"]);
        new_rare.strings.insert("rare-login-token".to_string());

        let mut old_common_a = fp(3, "Lo/CommonA;", &["a()->V"]);
        old_common_a
            .strings
            .insert("shared-common-value".to_string());
        let mut old_common_b = fp(4, "Lo/CommonB;", &["a()->V"]);
        old_common_b
            .strings
            .insert("shared-common-value".to_string());
        let mut old_common_c = fp(5, "Lo/CommonC;", &["a()->V"]);
        old_common_c
            .strings
            .insert("shared-common-value".to_string());
        let mut old_common_d = fp(6, "Lo/CommonD;", &["a()->V"]);
        old_common_d
            .strings
            .insert("shared-common-value".to_string());

        let old = AppFingerprint {
            classes: vec![
                old_rare,
                old_common_a,
                old_common_b,
                old_common_c,
                old_common_d,
            ],
        };
        let new = AppFingerprint {
            classes: vec![new_rare],
        };

        let stats = AnchorStats::build(&old, &new);

        assert!(stats.is_rare(AnchorKind::String, "rare-login-token"));
        assert!(!stats.is_rare(AnchorKind::String, "shared-common-value"));
    }

    #[test]
    fn anchor_stats_count_shared_anchor_kinds() {
        let mut old_class = fp(1, "Lo/A;", &["a(I)->V"]);
        old_class.strings.insert("rare-text".to_string());
        old_class
            .method_ref_shapes
            .insert("Lapi/Auth;->check()->Z".to_string());
        let mut new_class = fp(2, "Ln/A;", &["b(I)->V"]);
        new_class.strings.insert("rare-text".to_string());
        new_class
            .method_ref_shapes
            .insert("Lapi/Auth;->check()->Z".to_string());

        let old = AppFingerprint {
            classes: vec![old_class.clone()],
        };
        let new = AppFingerprint {
            classes: vec![new_class.clone()],
        };
        let stats = AnchorStats::build(&old, &new);
        let evidence = stats.rare_evidence(&old_class, &new_class);

        assert_eq!(evidence.total, 3);
        assert_eq!(evidence.kind_count, 3);
        assert_eq!(evidence.method_ref, 1);
        assert_eq!(evidence.method_proto, 1);
        assert_eq!(evidence.string, 1);
    }

    #[test]
    fn verified_only_accepts_rare_independent_anchors_with_stable_shape() {
        let mut old_class = fp(1, "Lo/Login;", &["a(I)->V", "b()->Z"]);
        old_class.strings.insert("rare-login-token".to_string());
        old_class
            .method_ref_shapes
            .insert("Lapi/Auth;->check()->Z".to_string());
        old_class
            .field_type_shapes
            .insert("Ljava/lang/String;".to_string());
        old_class.instruction_count = 80;
        old_class.opcode_histogram = BTreeMap::from([(0x6e, 3), (0x0e, 1)]);

        let mut new_class = fp(2, "Ln/Renamed;", &["x(I)->V", "y()->Z"]);
        new_class.strings.insert("rare-login-token".to_string());
        new_class
            .method_ref_shapes
            .insert("Lapi/Auth;->check()->Z".to_string());
        new_class
            .field_type_shapes
            .insert("Ljava/lang/String;".to_string());
        new_class.instruction_count = 60;
        new_class.opcode_histogram = BTreeMap::from([(0x6e, 3), (0x0e, 1)]);

        let result = match_classes(
            &AppFingerprint {
                classes: vec![old_class],
            },
            &AppFingerprint {
                classes: vec![new_class],
            },
            &MatchConfig {
                min_confidence: 0.80,
                low_confidence: 0.55,
                max_candidates: 10,
                verified_only: true,
            },
        );

        assert_eq!(result[0].status, MatchStatus::Matched);
        assert!(result[0]
            .reasons
            .iter()
            .any(|reason| reason == VERIFIED_RARE_ANCHORS_STABLE_SHAPE));
        assert!(result[0].reasons.iter().any(|reason| {
            reason == "rare anchors: string=1 method_ref=1 field_ref=0 method_proto=2 field_type=1"
        }));
    }

    #[test]
    fn common_anchor_does_not_create_verified_match() {
        let old_classes: Vec<_> = (0..4)
            .map(|offset| {
                let mut class = fp(10 + offset, &format!("Lo/Common{};", offset), &["a()->V"]);
                class.strings.insert("common-shared-anchor".to_string());
                class
            })
            .collect();
        let mut old_target = fp(1, "Lo/Target;", &["target(I)->V"]);
        old_target
            .strings
            .insert("common-shared-anchor".to_string());

        let mut new_target = fp(2, "Ln/Target;", &["renamed(I)->V"]);
        new_target
            .strings
            .insert("common-shared-anchor".to_string());

        let mut all_old = vec![old_target];
        all_old.extend(old_classes);

        let result = match_classes(
            &AppFingerprint { classes: all_old },
            &AppFingerprint {
                classes: vec![new_target],
            },
            &MatchConfig {
                min_confidence: 0.80,
                low_confidence: 0.10,
                max_candidates: 10,
                verified_only: true,
            },
        );

        let target = result
            .iter()
            .find(|item| item.old_class_id == Some(1))
            .expect("target result");
        assert_ne!(target.status, MatchStatus::Matched);
        assert!(!target
            .reasons
            .iter()
            .any(|reason| reason == VERIFIED_RARE_ANCHORS_STABLE_SHAPE));
    }

    #[test]
    fn ambiguous_rare_anchor_candidates_do_not_become_matched() {
        let mut old_class = fp(1, "Lo/A;", &["a(I)->V", "b()->Z"]);
        old_class.strings.insert("rare-token".to_string());
        old_class
            .method_ref_shapes
            .insert("Lapi/Auth;->check()->Z".to_string());
        old_class
            .field_type_shapes
            .insert("Ljava/lang/String;".to_string());
        old_class.instruction_count = 50;
        old_class.opcode_histogram = BTreeMap::from([(0x6e, 2), (0x0e, 1)]);

        let mut new_one = fp(10, "Ln/A1;", &["x(I)->V", "y()->Z"]);
        new_one.strings.insert("rare-token".to_string());
        new_one
            .method_ref_shapes
            .insert("Lapi/Auth;->check()->Z".to_string());
        new_one
            .field_type_shapes
            .insert("Ljava/lang/String;".to_string());
        new_one.instruction_count = 50;
        new_one.opcode_histogram = BTreeMap::from([(0x6e, 2), (0x0e, 1)]);

        let mut new_two = fp(20, "Ln/A2;", &["x(I)->V", "y()->Z"]);
        new_two.strings.insert("rare-token".to_string());
        new_two
            .method_ref_shapes
            .insert("Lapi/Auth;->check()->Z".to_string());
        new_two
            .field_type_shapes
            .insert("Ljava/lang/String;".to_string());
        new_two.instruction_count = 50;
        new_two.opcode_histogram = BTreeMap::from([(0x6e, 2), (0x0e, 1)]);

        let result = match_classes(
            &AppFingerprint {
                classes: vec![old_class],
            },
            &AppFingerprint {
                classes: vec![new_one, new_two],
            },
            &MatchConfig {
                min_confidence: 0.80,
                low_confidence: 0.55,
                max_candidates: 10,
                verified_only: true,
            },
        );

        assert_eq!(result[0].status, MatchStatus::Conflict);
    }

    fn verified_seed(id: usize, descriptor: &str) -> ClassFingerprint {
        fp(id, descriptor, &["seed()->V", "shape(I)->I"])
    }

    fn graph_target(
        id: usize,
        descriptor: &str,
        refs: &[&str],
        method_name: &str,
    ) -> ClassFingerprint {
        let method = format!("{method_name}(I)->V");
        let mut class = fp(id, descriptor, &[method.as_str()]);
        class.class_ref_shapes = refs.iter().map(|item| item.to_string()).collect();
        class.method_proto_shapes.insert("(I)->V".to_string());
        class.instruction_count = 40;
        class.opcode_histogram = BTreeMap::from([(0x6e, 2), (0x0e, 1)]);
        class
    }

    #[test]
    fn call_graph_verification_promotes_candidate_through_verified_neighbors() {
        let old_a = verified_seed(1, "Lpkg/A;");
        let old_b = verified_seed(2, "Lpkg/B;");
        let old_target = graph_target(3, "Lpkg/OldTarget;", &["Lpkg/A;", "Lpkg/B;"], "oldRun");

        let new_a = verified_seed(10, "Lpkg/A;");
        let new_b = verified_seed(20, "Lpkg/B;");
        let new_target = graph_target(30, "Lx/NewTarget;", &["Lpkg/A;", "Lpkg/B;"], "newRun");

        let result = match_classes(
            &AppFingerprint {
                classes: vec![old_a, old_b, old_target],
            },
            &AppFingerprint {
                classes: vec![new_a, new_b, new_target],
            },
            &MatchConfig {
                min_confidence: 0.80,
                low_confidence: 0.20,
                max_candidates: 10,
                verified_only: true,
            },
        );

        let target = result
            .iter()
            .find(|item| item.old_class_id == Some(3))
            .expect("target result");
        assert_eq!(target.status, MatchStatus::Matched);
        assert_eq!(target.new_class_id, Some(30));
        assert!(target
            .reasons
            .iter()
            .any(|reason| reason == VERIFIED_CALL_GRAPH_NEIGHBORHOOD));
        assert!(target
            .reasons
            .iter()
            .any(|reason| reason == "call graph verified edges: 2/2"));
    }

    #[test]
    fn conflicting_seeds_cannot_verify_their_neighbors() {
        let old_a = verified_seed(1, "Lpkg/A;");
        let old_b = fp(2, "Lpkg/B;", &["secondSeed()->Z", "other(J)->J"]);
        let old_target = graph_target(3, "Lpkg/OldTarget;", &["Lpkg/A;", "Lpkg/B;"], "oldRun");
        let duplicate_a = verified_seed(4, "Lpkg/DuplicateA;");
        let mut new_b = old_b.clone();
        new_b.class_id = 20;
        let result = match_classes(
            &AppFingerprint {
                classes: vec![old_a, old_b, old_target, duplicate_a],
            },
            &AppFingerprint {
                classes: vec![
                    verified_seed(10, "Lpkg/A;"),
                    new_b,
                    graph_target(30, "Lx/NewTarget;", &["Lpkg/A;", "Lpkg/B;"], "newRun"),
                ],
            },
            &MatchConfig {
                min_confidence: 0.80,
                low_confidence: 0.20,
                max_candidates: 10,
                verified_only: true,
            },
        );
        for id in [1, 4] {
            let seed = result
                .iter()
                .find(|item| item.old_class_id == Some(id))
                .expect("seed");
            assert_eq!(seed.status, MatchStatus::Conflict);
        }
        let target = result
            .iter()
            .find(|item| item.old_class_id == Some(3))
            .expect("target");
        assert_ne!(target.status, MatchStatus::Matched);
        assert!(!target
            .reasons
            .iter()
            .any(|reason| reason == VERIFIED_CALL_GRAPH_NEIGHBORHOOD));
    }

    #[test]
    fn call_graph_verification_rejects_weak_edge_ratio() {
        let old_a = verified_seed(1, "Lpkg/A;");
        let old_b = verified_seed(2, "Lpkg/B;");
        let old_target = graph_target(3, "Lpkg/OldTarget;", &["Lpkg/A;", "Lpkg/B;"], "oldRun");

        let new_a = verified_seed(10, "Lpkg/A;");
        let new_b = verified_seed(20, "Lpkg/B;");
        let new_target = graph_target(30, "Lx/NewTarget;", &["Lpkg/A;"], "newRun");

        let result = match_classes(
            &AppFingerprint {
                classes: vec![old_a, old_b, old_target],
            },
            &AppFingerprint {
                classes: vec![new_a, new_b, new_target],
            },
            &MatchConfig {
                min_confidence: 0.80,
                low_confidence: 0.20,
                max_candidates: 10,
                verified_only: true,
            },
        );

        let target = result
            .iter()
            .find(|item| item.old_class_id == Some(3))
            .expect("target result");
        assert_ne!(target.status, MatchStatus::Matched);
        assert!(!target
            .reasons
            .iter()
            .any(|reason| reason == VERIFIED_CALL_GRAPH_NEIGHBORHOOD));
    }

    #[test]
    fn candidate_list_respects_max_candidates_after_pruning() {
        let old = AppFingerprint {
            classes: vec![fp(1, "La/A;", &["a()->V"])],
        };
        let new = AppFingerprint {
            classes: (0..20)
                .map(|id| fp(100 + id, &format!("Lx/C{};", id), &["a()->V"]))
                .collect(),
        };
        let result = match_classes(
            &old,
            &new,
            &MatchConfig {
                min_confidence: 0.95,
                low_confidence: 0.10,
                max_candidates: 3,
                verified_only: false,
            },
        );
        assert!(result[0].candidates.len() <= 3);
    }

    #[test]
    fn propagation_is_deterministic() {
        let old = AppFingerprint {
            classes: vec![fp(1, "La/A;", &["a()->V"]), fp(2, "La/B;", &["b()->V"])],
        };
        let new = AppFingerprint {
            classes: vec![fp(10, "Lx/A;", &["a()->V"]), fp(20, "Lx/B;", &["b()->V"])],
        };
        let config = MatchConfig {
            min_confidence: 0.70,
            low_confidence: 0.40,
            max_candidates: 5,
            verified_only: false,
        };
        let first = match_classes(&old, &new, &config);
        let second = match_classes(&old, &new, &config);
        assert_eq!(first, second);
    }

    #[test]
    fn matches_methods_and_fields_inside_matched_classes() {
        let old_model = member_model(1, "La/B;", 10, 20);
        let new_model = member_model(2, "La/B;", 30, 40);
        let old_fp = fingerprint_app(&old_model);
        let new_fp = fingerprint_app(&new_model);

        let report = match_app_models(
            &old_model,
            &new_model,
            &old_fp,
            &new_fp,
            &MatchConfig {
                min_confidence: 0.80,
                low_confidence: 0.55,
                max_candidates: 10,
                verified_only: false,
            },
        );

        assert_eq!(report.methods.len(), 1);
        assert_eq!(report.fields.len(), 1);
        assert_eq!(report.methods[0].status, MatchStatus::Matched);
        assert_eq!(report.fields[0].status, MatchStatus::Matched);
    }

    #[test]
    fn matches_renamed_methods_by_bytecode_shape() {
        let old_model = member_model_with_method("La/B;", "a", 10, Some(code_summary()));
        let new_model = member_model_with_method("La/B;", "x", 30, Some(code_summary()));
        let old_fp = fingerprint_app(&old_model);
        let new_fp = fingerprint_app(&new_model);

        let report = match_app_models(
            &old_model,
            &new_model,
            &old_fp,
            &new_fp,
            &MatchConfig {
                min_confidence: 0.80,
                low_confidence: 0.55,
                max_candidates: 10,
                verified_only: false,
            },
        );

        assert_eq!(report.methods.len(), 1);
        assert_eq!(report.methods[0].status, MatchStatus::Matched);
        assert_eq!(report.methods[0].new_member_id, Some(30));
        assert!(report.methods[0]
            .reasons
            .iter()
            .any(|reason| reason.contains("bytecode score")));
    }

    fn member_model(
        class_id: usize,
        descriptor: &str,
        method_id: usize,
        field_id: usize,
    ) -> AppModel {
        AppModel {
            apk_name: "app.apk".to_string(),
            package_name: None,
            classes: vec![ClassModel {
                id: class_id,
                descriptor: descriptor.to_string(),
                access_flags: 1,
                superclass: Some("Ljava/lang/Object;".to_string()),
                interfaces: Vec::new(),
                methods: vec![MethodModel {
                    id: method_id,
                    owner_class: descriptor.to_string(),
                    name: "run".to_string(),
                    return_type: "V".to_string(),
                    parameters: vec!["I".to_string()],
                    access_flags: 1,
                    code: None,
                }],
                fields: vec![FieldModel {
                    id: field_id,
                    owner_class: descriptor.to_string(),
                    name: "count".to_string(),
                    field_type: "I".to_string(),
                    access_flags: 1,
                }],
                origin: DexOrigin {
                    apk_part: "base.apk".to_string(),
                    dex_file: "classes.dex".to_string(),
                    dex_index: 0,
                    class_def_index: Some(0),
                },
            }],
            coverage: ParseCoverage::default(),
        }
    }

    fn member_model_with_method(
        descriptor: &str,
        method_name: &str,
        method_id: usize,
        code: Option<MethodCodeSummary>,
    ) -> AppModel {
        AppModel {
            apk_name: "app.apk".to_string(),
            package_name: None,
            classes: vec![ClassModel {
                id: 1,
                descriptor: descriptor.to_string(),
                access_flags: 1,
                superclass: Some("Ljava/lang/Object;".to_string()),
                interfaces: Vec::new(),
                methods: vec![MethodModel {
                    id: method_id,
                    owner_class: descriptor.to_string(),
                    name: method_name.to_string(),
                    return_type: "V".to_string(),
                    parameters: vec!["I".to_string()],
                    access_flags: 1,
                    code,
                }],
                fields: Vec::new(),
                origin: DexOrigin {
                    apk_part: "base.apk".to_string(),
                    dex_file: "classes.dex".to_string(),
                    dex_index: 0,
                    class_def_index: Some(0),
                },
            }],
            coverage: ParseCoverage::default(),
        }
    }

    fn code_summary() -> MethodCodeSummary {
        MethodCodeSummary {
            registers_size: 3,
            ins_size: 1,
            outs_size: 1,
            instruction_count: 10,
            opcode_histogram: BTreeMap::from([(0x1a, 1), (0x6e, 1), (0x0e, 1)]),
            string_refs: vec!["login".to_string()],
            method_refs: vec!["Lsdk/Auth;->check(I)->Z".to_string()],
            field_refs: vec!["Lsdk/Auth;->state:I".to_string()],
            branch_count: 1,
            return_count: 1,
            throw_count: 0,
            switch_count: 0,
        }
    }
}
