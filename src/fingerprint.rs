use std::collections::{BTreeMap, BTreeSet};

use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::dex::descriptor::package_shape;
use crate::model::{AppModel, ClassModel, FieldModel, MethodModel};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppFingerprint {
    pub classes: Vec<ClassFingerprint>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClassFingerprint {
    pub class_id: usize,
    pub descriptor: String,
    pub package_shape: String,
    pub superclass: Option<String>,
    pub interfaces: BTreeSet<String>,
    pub access_flags: u32,
    pub method_shapes: BTreeSet<String>,
    pub method_proto_shapes: BTreeSet<String>,
    pub field_shapes: BTreeSet<String>,
    pub field_type_shapes: BTreeSet<String>,
    pub strings: BTreeSet<String>,
    pub method_ref_shapes: BTreeSet<String>,
    pub field_ref_shapes: BTreeSet<String>,
    pub class_ref_shapes: BTreeSet<String>,
    pub instruction_count: u32,
    pub opcode_histogram: BTreeMap<u8, u32>,
}

pub fn fingerprint_app(app: &AppModel) -> AppFingerprint {
    let mut classes: Vec<_> = app.classes.par_iter().map(fingerprint_class).collect();
    classes.sort_by(|left, right| left.descriptor.cmp(&right.descriptor));
    AppFingerprint { classes }
}

fn fingerprint_class(class: &ClassModel) -> ClassFingerprint {
    let method_shapes = class.methods.iter().map(method_shape).collect();
    let method_proto_shapes = class.methods.iter().map(method_proto_shape).collect();
    let field_shapes = class.fields.iter().map(field_shape).collect();
    let field_type_shapes = class.fields.iter().map(field_type_shape).collect();
    let mut strings = BTreeSet::new();
    let mut method_ref_shapes = BTreeSet::new();
    let mut field_ref_shapes = BTreeSet::new();
    let mut class_ref_shapes = BTreeSet::new();
    if let Some(superclass) = &class.superclass {
        class_ref_shapes.insert(superclass.clone());
    }
    class_ref_shapes.extend(class.interfaces.iter().cloned());
    let mut opcode_histogram = BTreeMap::new();
    let instruction_count = class
        .methods
        .iter()
        .filter_map(|method| method.code.as_ref())
        .map(|code| {
            strings.extend(code.string_refs.iter().take(128).cloned());
            method_ref_shapes.extend(code.method_refs.iter().take(256).cloned());
            field_ref_shapes.extend(code.field_refs.iter().take(256).cloned());
            for method_ref in code.method_refs.iter().take(256) {
                if let Some(owner) = owner_descriptor_from_ref_shape(method_ref) {
                    class_ref_shapes.insert(owner.to_string());
                }
            }
            for field_ref in code.field_refs.iter().take(256) {
                if let Some(owner) = owner_descriptor_from_ref_shape(field_ref) {
                    class_ref_shapes.insert(owner.to_string());
                }
            }
            for (opcode, count) in &code.opcode_histogram {
                *opcode_histogram.entry(*opcode).or_insert(0) += count;
            }
            code.instruction_count
        })
        .sum();

    ClassFingerprint {
        class_id: class.id,
        descriptor: class.descriptor.clone(),
        package_shape: package_shape(&class.descriptor),
        superclass: class.superclass.clone(),
        interfaces: class.interfaces.iter().cloned().collect(),
        access_flags: class.access_flags,
        method_shapes,
        method_proto_shapes,
        field_shapes,
        field_type_shapes,
        strings,
        method_ref_shapes,
        field_ref_shapes,
        class_ref_shapes,
        instruction_count,
        opcode_histogram,
    }
}

fn method_shape(method: &MethodModel) -> String {
    format!(
        "{}({})->{}",
        method.name,
        method.parameters.join(","),
        method.return_type
    )
}

fn method_proto_shape(method: &MethodModel) -> String {
    format!("({})->{}", method.parameters.join(","), method.return_type)
}

fn field_shape(field: &FieldModel) -> String {
    format!("{}:{}", field.name, field.field_type)
}

fn field_type_shape(field: &FieldModel) -> String {
    field.field_type.clone()
}

fn owner_descriptor_from_ref_shape(value: &str) -> Option<&str> {
    value.split_once("->").map(|(owner, _)| owner)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::model::{
        AppModel, ClassModel, DexOrigin, FieldModel, MethodCodeSummary, MethodModel, ParseCoverage,
    };

    use super::fingerprint_app;

    #[test]
    fn fingerprints_are_sorted_and_deterministic() {
        let app = test_app_with_one_class();

        let fp = fingerprint_app(&app);
        assert_eq!(fp.classes[0].package_shape, "*.*");
        assert!(fp.classes[0].method_shapes.contains("a(I)->V"));
        assert!(fp.classes[0].method_proto_shapes.contains("(I)->V"));
        assert!(fp.classes[0].field_shapes.contains("b:I"));
        assert!(fp.classes[0].field_type_shapes.contains("I"));
    }

    #[test]
    fn fingerprints_include_method_code_refs() {
        let mut app = test_app_with_one_class();
        app.classes[0].methods[0].code = Some(MethodCodeSummary {
            registers_size: 3,
            ins_size: 1,
            outs_size: 2,
            instruction_count: 10,
            opcode_histogram: BTreeMap::from([(0x0e, 1)]),
            string_refs: vec!["login".to_string()],
            method_refs: vec!["sdk:android/view/View->setOnClickListener".to_string()],
            field_refs: vec!["local:int".to_string()],
            branch_count: 1,
            return_count: 1,
            throw_count: 0,
            switch_count: 0,
        });

        let fp = fingerprint_app(&app);

        assert_eq!(fp.classes[0].instruction_count, 10);
        assert!(fp.classes[0].strings.contains("login"));
        assert!(fp.classes[0]
            .method_ref_shapes
            .contains("sdk:android/view/View->setOnClickListener"));
        assert!(fp.classes[0].field_ref_shapes.contains("local:int"));
    }

    #[test]
    fn fingerprints_include_class_reference_shapes() {
        let mut app = test_app_with_one_class();
        app.classes[0].superclass = Some("Lpkg/Base;".to_string());
        app.classes[0].interfaces = vec!["Lpkg/Interface;".to_string()];
        app.classes[0].methods[0].code = Some(MethodCodeSummary {
            registers_size: 3,
            ins_size: 1,
            outs_size: 2,
            instruction_count: 10,
            opcode_histogram: BTreeMap::from([(0x6e, 1), (0x52, 1)]),
            string_refs: Vec::new(),
            method_refs: vec!["Lpkg/Service;->call(I)->V".to_string()],
            field_refs: vec!["Lpkg/State;->value:I".to_string()],
            branch_count: 0,
            return_count: 1,
            throw_count: 0,
            switch_count: 0,
        });

        let fp = fingerprint_app(&app);
        let refs = &fp.classes[0].class_ref_shapes;

        assert!(refs.contains("Lpkg/Base;"));
        assert!(refs.contains("Lpkg/Interface;"));
        assert!(refs.contains("Lpkg/Service;"));
        assert!(refs.contains("Lpkg/State;"));
    }

    fn test_app_with_one_class() -> AppModel {
        AppModel {
            apk_name: "app.apk".to_string(),
            package_name: None,
            classes: vec![ClassModel {
                id: 1,
                descriptor: "La/b/C;".to_string(),
                access_flags: 1,
                superclass: Some("Ljava/lang/Object;".to_string()),
                interfaces: vec!["Ljava/io/Serializable;".to_string()],
                methods: vec![MethodModel {
                    id: 1,
                    owner_class: "La/b/C;".to_string(),
                    name: "a".to_string(),
                    return_type: "V".to_string(),
                    parameters: vec!["I".to_string()],
                    access_flags: 1,
                    code: None,
                }],
                fields: vec![FieldModel {
                    id: 1,
                    owner_class: "La/b/C;".to_string(),
                    name: "b".to_string(),
                    field_type: "I".to_string(),
                    access_flags: 2,
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
}
