use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::apk::ApkInput;
use crate::dex::{parse_dex, ParsedDex};
use crate::error::Result;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DexOrigin {
    pub apk_part: String,
    pub dex_file: String,
    pub dex_index: usize,
    pub class_def_index: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppModel {
    pub apk_name: String,
    pub package_name: Option<String>,
    pub classes: Vec<ClassModel>,
    pub coverage: ParseCoverage,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ParseCoverage {
    pub apk_parts: usize,
    pub dex_files: usize,
    pub parsed_classes: usize,
    pub parsed_methods: usize,
    pub parsed_fields: usize,
    pub warnings: Vec<ModelWarning>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModelWarning {
    pub origin: String,
    pub kind: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClassModel {
    pub id: usize,
    pub descriptor: String,
    pub access_flags: u32,
    pub superclass: Option<String>,
    pub interfaces: Vec<String>,
    pub methods: Vec<MethodModel>,
    pub fields: Vec<FieldModel>,
    pub origin: DexOrigin,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MethodModel {
    pub id: usize,
    pub owner_class: String,
    pub name: String,
    pub return_type: String,
    pub parameters: Vec<String>,
    pub access_flags: u32,
    pub code: Option<MethodCodeSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MethodCodeSummary {
    pub registers_size: u16,
    pub ins_size: u16,
    pub outs_size: u16,
    pub instruction_count: u32,
    pub opcode_histogram: BTreeMap<u8, u32>,
    pub string_refs: Vec<String>,
    pub method_refs: Vec<String>,
    pub field_refs: Vec<String>,
    pub branch_count: u32,
    pub return_count: u32,
    pub throw_count: u32,
    pub switch_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FieldModel {
    pub id: usize,
    pub owner_class: String,
    pub name: String,
    pub field_type: String,
    pub access_flags: u32,
}

pub fn build_app_model(input: &ApkInput, parsed_dex: &[ParsedDex]) -> Result<AppModel> {
    let mut state = ModelBuildState::default();

    for (dex_index, parsed) in parsed_dex.iter().enumerate() {
        let dex_name = input
            .dex_files
            .get(dex_index)
            .map(|dex| dex.name.clone())
            .unwrap_or_else(|| format!("classes{}.dex", dex_index + 1));
        let apk_part = input
            .dex_files
            .get(dex_index)
            .map(|dex| dex.apk_part.clone())
            .unwrap_or_else(|| apk_name_for_origin(input));

        state.append_parsed_dex(parsed, &apk_part, &dex_name, dex_index);
    }

    Ok(state.finish(
        apk_name_for_model(input.path.as_path()),
        input.package_name.clone(),
        input.apk_parts,
        input.dex_files.len(),
    ))
}

pub fn build_app_model_streaming(input: ApkInput) -> Result<AppModel> {
    let ApkInput {
        path,
        package_name,
        apk_parts,
        dex_files,
    } = input;
    let apk_name = apk_name_for_model(path.as_path());
    let dex_count = dex_files.len();
    let mut state = ModelBuildState::default();

    for (dex_index, dex) in dex_files.into_iter().enumerate() {
        let parsed = parse_dex(&dex.bytes)?;
        state.append_parsed_dex(&parsed, &dex.apk_part, &dex.name, dex_index);
    }

    Ok(state.finish(apk_name, package_name, apk_parts, dex_count))
}

#[derive(Default)]
struct ModelBuildState {
    classes: Vec<ClassModel>,
    next_class_id: usize,
    next_method_id: usize,
    next_field_id: usize,
    warnings: Vec<ModelWarning>,
}

impl ModelBuildState {
    fn append_parsed_dex(
        &mut self,
        parsed: &ParsedDex,
        apk_part: &str,
        dex_name: &str,
        dex_index: usize,
    ) {
        self.warnings
            .extend(parsed.raw.warnings.iter().map(|warning| ModelWarning {
                origin: format!("{}!{}:{}", apk_part, dex_name, warning.origin),
                kind: format!("{:?}", warning.kind),
                message: warning.message.clone(),
            }));

        for (class_def_index, class_def) in parsed.raw.classes.iter().enumerate() {
            let mut fields = Vec::new();
            let mut methods = Vec::new();

            if let Some(class_data) = &class_def.class_data {
                for encoded in class_data
                    .static_fields
                    .iter()
                    .chain(class_data.instance_fields.iter())
                {
                    if let Some(field_id) = parsed.raw.fields.get(encoded.field_idx as usize) {
                        fields.push(FieldModel {
                            id: self.next_field_id,
                            owner_class: class_def.class_type.clone(),
                            name: field_id.name.clone(),
                            field_type: field_id.field_type.clone(),
                            access_flags: encoded.access_flags,
                        });
                        self.next_field_id += 1;
                    }
                }

                for encoded in class_data
                    .direct_methods
                    .iter()
                    .chain(class_data.virtual_methods.iter())
                {
                    if let Some(method_id) = parsed.raw.methods.get(encoded.method_idx as usize) {
                        let code = parsed
                            .raw
                            .code_items
                            .get(&encoded.code_off)
                            .map(|code_item| {
                                method_code_summary_from_code_item(code_item, &parsed.raw)
                            });
                        methods.push(MethodModel {
                            id: self.next_method_id,
                            owner_class: class_def.class_type.clone(),
                            name: method_id.name.clone(),
                            return_type: method_id.proto.return_type.clone(),
                            parameters: method_id.proto.parameters.clone(),
                            access_flags: encoded.access_flags,
                            code,
                        });
                        self.next_method_id += 1;
                    }
                }
            }

            self.classes.push(ClassModel {
                id: self.next_class_id,
                descriptor: class_def.class_type.clone(),
                access_flags: class_def.access_flags,
                superclass: class_def.superclass.clone(),
                interfaces: class_def.interfaces.clone(),
                methods,
                fields,
                origin: DexOrigin {
                    apk_part: apk_part.to_string(),
                    dex_file: dex_name.to_string(),
                    dex_index,
                    class_def_index: Some(class_def_index),
                },
            });
            self.next_class_id += 1;
        }
    }

    fn finish(
        mut self,
        apk_name: String,
        package_name: Option<String>,
        apk_parts: usize,
        dex_files: usize,
    ) -> AppModel {
        self.classes
            .sort_by(|left, right| left.descriptor.cmp(&right.descriptor));
        let coverage = ParseCoverage {
            apk_parts,
            dex_files,
            parsed_classes: self.classes.len(),
            parsed_methods: self.classes.iter().map(|class| class.methods.len()).sum(),
            parsed_fields: self.classes.iter().map(|class| class.fields.len()).sum(),
            warnings: self.warnings,
        };

        AppModel {
            apk_name,
            package_name,
            classes: self.classes,
            coverage,
        }
    }
}

fn apk_name_for_origin(input: &ApkInput) -> String {
    input
        .path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("input.apk")
        .to_string()
}

fn apk_name_for_model(path: &std::path::Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("apk")
        .to_string()
}

fn method_code_summary_from_code_item(
    code_item: &crate::dex::raw::CodeItem,
    raw: &crate::dex::raw::RawDex,
) -> MethodCodeSummary {
    MethodCodeSummary {
        registers_size: code_item.registers_size,
        ins_size: code_item.ins_size,
        outs_size: code_item.outs_size,
        instruction_count: code_item.instruction_summary.instruction_count,
        opcode_histogram: code_item.instruction_summary.opcode_histogram.clone(),
        string_refs: code_item
            .instruction_summary
            .string_refs
            .iter()
            .filter_map(|id| raw.strings.get(*id as usize).cloned())
            .collect(),
        method_refs: code_item
            .instruction_summary
            .method_refs
            .iter()
            .filter_map(|id| raw.methods.get(*id as usize))
            .map(method_ref_shape)
            .collect(),
        field_refs: code_item
            .instruction_summary
            .field_refs
            .iter()
            .filter_map(|id| raw.fields.get(*id as usize))
            .map(field_ref_shape)
            .collect(),
        branch_count: code_item.instruction_summary.branch_count,
        return_count: code_item.instruction_summary.return_count,
        throw_count: code_item.instruction_summary.throw_count,
        switch_count: code_item.instruction_summary.switch_count,
    }
}

fn method_ref_shape(method: &crate::dex::raw::MethodId) -> String {
    format!(
        "{}->{}({})->{}",
        method.class_type,
        method.name,
        method.proto.parameters.join(","),
        method.proto.return_type
    )
}

fn field_ref_shape(field: &crate::dex::raw::FieldId) -> String {
    format!("{}->{}:{}", field.class_type, field.name, field.field_type)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use crate::apk::{ApkInput, DexBlob};
    use crate::dex::raw::RawDex;
    use crate::dex::ParsedDex;

    use super::build_app_model;

    #[test]
    fn preserves_class_dex_origin() {
        let input = ApkInput {
            path: PathBuf::from("old.apk"),
            package_name: Some("com.example".to_string()),
            apk_parts: 1,
            dex_files: vec![DexBlob {
                apk_part: "base.apk".to_string(),
                name: "classes2.dex".to_string(),
                dex_index: 0,
                bytes: Vec::new(),
            }],
        };
        let mut raw = RawDex::empty_for_test();
        raw.classes.push(crate::dex::raw::ClassDef {
            class_type: "La/b/C;".to_string(),
            access_flags: 1,
            superclass: Some("Ljava/lang/Object;".to_string()),
            interfaces: Vec::new(),
            source_file: None,
            class_data_off: 0,
            class_data: None,
        });
        let model = build_app_model(&input, &[ParsedDex { raw }]).expect("model");
        assert_eq!(model.classes[0].origin.dex_file, "classes2.dex");
        assert_eq!(model.classes[0].origin.class_def_index, Some(0));
    }

    #[test]
    fn model_keeps_empty_member_lists_for_classes_without_class_data() {
        let input = ApkInput {
            path: PathBuf::from("old.apk"),
            package_name: None,
            apk_parts: 1,
            dex_files: vec![DexBlob {
                apk_part: "base.apk".to_string(),
                name: "classes.dex".to_string(),
                dex_index: 0,
                bytes: Vec::new(),
            }],
        };
        let mut raw = RawDex::empty_for_test();
        raw.classes.push(crate::dex::raw::ClassDef {
            class_type: "La/B;".to_string(),
            access_flags: 1,
            superclass: None,
            interfaces: Vec::new(),
            source_file: None,
            class_data_off: 0,
            class_data: None,
        });
        let model = build_app_model(&input, &[ParsedDex { raw }]).expect("model");
        assert!(model.classes[0].methods.is_empty());
        assert!(model.classes[0].fields.is_empty());
    }

    #[test]
    fn model_populates_members_from_class_data() {
        let input = ApkInput {
            path: PathBuf::from("old.apk"),
            package_name: None,
            apk_parts: 1,
            dex_files: vec![DexBlob {
                apk_part: "base.apk".to_string(),
                name: "classes.dex".to_string(),
                dex_index: 0,
                bytes: Vec::new(),
            }],
        };
        let mut raw = RawDex::empty_for_test();
        raw.fields.push(crate::dex::raw::FieldId {
            class_type: "La/B;".to_string(),
            field_type: "I".to_string(),
            name: "count".to_string(),
        });
        raw.methods.push(crate::dex::raw::MethodId {
            class_type: "La/B;".to_string(),
            name: "run".to_string(),
            proto: crate::dex::raw::ProtoId {
                shorty: "V".to_string(),
                return_type: "V".to_string(),
                parameters: vec!["I".to_string()],
            },
        });
        raw.classes.push(crate::dex::raw::ClassDef {
            class_type: "La/B;".to_string(),
            access_flags: 1,
            superclass: None,
            interfaces: Vec::new(),
            source_file: None,
            class_data_off: 1,
            class_data: Some(crate::dex::class_data::EncodedClassData {
                static_fields: vec![crate::dex::class_data::EncodedField {
                    field_idx: 0,
                    access_flags: 2,
                }],
                instance_fields: Vec::new(),
                direct_methods: vec![crate::dex::class_data::EncodedMethod {
                    method_idx: 0,
                    access_flags: 1,
                    code_off: 0,
                }],
                virtual_methods: Vec::new(),
            }),
        });

        let model = build_app_model(&input, &[ParsedDex { raw }]).expect("model");
        assert_eq!(model.classes[0].fields[0].name, "count");
        assert_eq!(model.classes[0].fields[0].field_type, "I");
        assert_eq!(model.classes[0].methods[0].name, "run");
        assert_eq!(model.classes[0].methods[0].parameters, vec!["I"]);
    }

    #[test]
    fn method_model_keeps_code_summary_when_available() {
        let input = ApkInput {
            path: PathBuf::from("old.apk"),
            package_name: None,
            apk_parts: 1,
            dex_files: vec![DexBlob {
                apk_part: "base.apk".to_string(),
                name: "classes.dex".to_string(),
                dex_index: 0,
                bytes: Vec::new(),
            }],
        };
        let mut raw = RawDex::empty_for_test();
        raw.methods.push(crate::dex::raw::MethodId {
            class_type: "La/B;".to_string(),
            name: "run".to_string(),
            proto: crate::dex::raw::ProtoId {
                shorty: "V".to_string(),
                return_type: "V".to_string(),
                parameters: Vec::new(),
            },
        });
        raw.code_items.insert(
            100,
            crate::dex::raw::CodeItem {
                registers_size: 2,
                ins_size: 1,
                outs_size: 0,
                tries_size: 0,
                debug_info_off: 0,
                insns_size: 1,
                instruction_summary: crate::dex::instructions::InstructionSummary {
                    instruction_count: 1,
                    opcode_histogram: BTreeMap::from([(0x0e, 1)]),
                    return_count: 1,
                    ..Default::default()
                },
            },
        );
        raw.classes.push(crate::dex::raw::ClassDef {
            class_type: "La/B;".to_string(),
            access_flags: 1,
            superclass: None,
            interfaces: Vec::new(),
            source_file: None,
            class_data_off: 1,
            class_data: Some(crate::dex::class_data::EncodedClassData {
                static_fields: Vec::new(),
                instance_fields: Vec::new(),
                direct_methods: vec![crate::dex::class_data::EncodedMethod {
                    method_idx: 0,
                    access_flags: 1,
                    code_off: 100,
                }],
                virtual_methods: Vec::new(),
            }),
        });

        let model = build_app_model(&input, &[ParsedDex { raw }]).expect("model");
        let code = model.classes[0].methods[0].code.as_ref().expect("code");
        assert_eq!(code.instruction_count, 1);
        assert_eq!(code.return_count, 1);
    }
}
