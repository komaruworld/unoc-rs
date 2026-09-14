use std::collections::{BTreeMap, BTreeSet};

const ACC_ABSTRACT: u32 = 0x0400;
const ACC_INTERFACE: u32 = 0x0200;
const ACC_PUBLIC: u32 = 0x0001;
const ACC_STATIC: u32 = 0x0008;
const HEADER_SIZE: usize = 112;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct MethodRef {
    pub owner: String,
    pub name: String,
    pub parameters: Vec<String>,
    pub return_type: String,
}

impl MethodRef {
    pub fn new(owner: &str, name: &str, parameters: &[&str], return_type: &str) -> Self {
        Self {
            owner: owner.to_string(),
            name: name.to_string(),
            parameters: parameters
                .iter()
                .map(|parameter| (*parameter).to_string())
                .collect(),
            return_type: return_type.to_string(),
        }
    }

    fn proto(&self) -> ProtoRef {
        ProtoRef {
            parameters: self.parameters.clone(),
            return_type: self.return_type.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FieldRef {
    pub owner: String,
    pub name: String,
    pub field_type: String,
}

impl FieldRef {
    pub fn new(owner: &str, name: &str, field_type: &str) -> Self {
        Self {
            owner: owner.to_string(),
            name: name.to_string(),
            field_type: field_type.to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Instruction {
    ConstClass(String),
    InvokeVirtual(MethodRef),
    InvokeDirect(MethodRef),
    InvokeStatic(MethodRef),
    InvokeInterface(MethodRef),
    InvokeInterfaceRange(MethodRef),
    ReadInstanceField(FieldRef),
    ReadStaticField(FieldRef),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodKind {
    Direct,
    Static,
    Virtual,
    AbstractVirtual,
}

#[derive(Debug, Clone)]
pub struct MethodSpec {
    pub reference: MethodRef,
    pub kind: MethodKind,
    pub code: Vec<Instruction>,
}

impl MethodSpec {
    pub fn direct_method(reference: MethodRef) -> Self {
        Self {
            reference,
            kind: MethodKind::Direct,
            code: Vec::new(),
        }
    }

    pub fn virtual_method(reference: MethodRef) -> Self {
        Self {
            reference,
            kind: MethodKind::Virtual,
            code: Vec::new(),
        }
    }

    pub fn abstract_virtual(reference: MethodRef) -> Self {
        Self {
            reference,
            kind: MethodKind::AbstractVirtual,
            code: Vec::new(),
        }
    }

    pub fn static_with_code(reference: MethodRef, code: Vec<Instruction>) -> Self {
        Self {
            reference,
            kind: MethodKind::Static,
            code,
        }
    }

    pub fn static_method(reference: MethodRef) -> Self {
        Self {
            reference,
            kind: MethodKind::Static,
            code: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FieldSpec {
    pub reference: FieldRef,
    pub is_static: bool,
}

impl FieldSpec {
    pub fn instance(reference: FieldRef) -> Self {
        Self {
            reference,
            is_static: false,
        }
    }

    pub fn static_field(reference: FieldRef) -> Self {
        Self {
            reference,
            is_static: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClassSpec {
    pub descriptor: String,
    pub superclass: Option<String>,
    pub interfaces: Vec<String>,
    pub is_interface: bool,
    pub methods: Vec<MethodSpec>,
    pub fields: Vec<FieldSpec>,
}

impl ClassSpec {
    pub fn new(descriptor: &str) -> Self {
        Self {
            descriptor: descriptor.to_string(),
            superclass: Some("Ljava/lang/Object;".to_string()),
            interfaces: Vec::new(),
            is_interface: false,
            methods: Vec::new(),
            fields: Vec::new(),
        }
    }

    pub fn interface(descriptor: &str) -> Self {
        Self {
            descriptor: descriptor.to_string(),
            superclass: Some("Ljava/lang/Object;".to_string()),
            interfaces: Vec::new(),
            is_interface: true,
            methods: Vec::new(),
            fields: Vec::new(),
        }
    }

    pub fn with_superclass(mut self, superclass: &str) -> Self {
        self.superclass = Some(superclass.to_string());
        self
    }

    pub fn without_superclass(mut self) -> Self {
        self.superclass = None;
        self
    }

    pub fn with_interface(mut self, interface: &str) -> Self {
        self.interfaces.push(interface.to_string());
        self
    }

    pub fn with_method(mut self, method: MethodSpec) -> Self {
        self.methods.push(method);
        self
    }

    pub fn with_field(mut self, field: FieldSpec) -> Self {
        self.fields.push(field);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ProtoRef {
    parameters: Vec<String>,
    return_type: String,
}

pub fn empty_dex_header(version: &str) -> Vec<u8> {
    let mut bytes = vec![0u8; HEADER_SIZE];
    bytes[0..4].copy_from_slice(b"dex\n");
    bytes[4..7].copy_from_slice(version.as_bytes());
    bytes[7] = 0;
    write_u32(&mut bytes, 32, HEADER_SIZE as u32);
    write_u32(&mut bytes, 36, HEADER_SIZE as u32);
    write_u32(&mut bytes, 40, 0x12345678);
    write_u32(&mut bytes, 52, HEADER_SIZE as u32);
    bytes
}

pub fn build_dex(classes: &[ClassSpec]) -> Vec<u8> {
    let tables = FixtureTables::collect(classes);
    DexWriter::new(classes, tables).write()
}

pub fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[derive(Debug)]
struct FixtureTables {
    strings: Vec<String>,
    string_indexes: BTreeMap<String, u32>,
    types: Vec<String>,
    type_indexes: BTreeMap<String, u32>,
    protos: Vec<ProtoRef>,
    proto_indexes: BTreeMap<ProtoRef, u32>,
    fields: Vec<FieldRef>,
    field_indexes: BTreeMap<FieldRef, u32>,
    methods: Vec<MethodRef>,
    method_indexes: BTreeMap<MethodRef, u32>,
}

impl FixtureTables {
    fn collect(classes: &[ClassSpec]) -> Self {
        let mut strings = BTreeSet::new();
        let mut types = BTreeSet::new();
        let mut protos = BTreeSet::new();
        let mut fields = BTreeSet::new();
        let mut methods = BTreeSet::new();

        for class in classes {
            collect_type(&class.descriptor, &mut strings, &mut types);
            if let Some(superclass) = &class.superclass {
                collect_type(superclass, &mut strings, &mut types);
            }
            for interface in &class.interfaces {
                collect_type(interface, &mut strings, &mut types);
            }
            for field in &class.fields {
                collect_field(&field.reference, &mut strings, &mut types, &mut fields);
            }
            for method in &class.methods {
                collect_method(
                    &method.reference,
                    &mut strings,
                    &mut types,
                    &mut protos,
                    &mut methods,
                );
                for instruction in &method.code {
                    collect_instruction(
                        instruction,
                        &mut strings,
                        &mut types,
                        &mut protos,
                        &mut fields,
                        &mut methods,
                    );
                }
            }
        }

        let strings = strings.into_iter().collect::<Vec<_>>();
        let types = types.into_iter().collect::<Vec<_>>();
        let protos = protos.into_iter().collect::<Vec<_>>();
        let fields = fields.into_iter().collect::<Vec<_>>();
        let methods = methods.into_iter().collect::<Vec<_>>();
        Self {
            string_indexes: index_values(&strings),
            type_indexes: index_values(&types),
            proto_indexes: index_values(&protos),
            field_indexes: index_values(&fields),
            method_indexes: index_values(&methods),
            strings,
            types,
            protos,
            fields,
            methods,
        }
    }
}

struct DexWriter<'a> {
    classes: &'a [ClassSpec],
    tables: FixtureTables,
    string_ids_off: usize,
    type_ids_off: usize,
    proto_ids_off: usize,
    field_ids_off: usize,
    method_ids_off: usize,
    class_defs_off: usize,
    data_off: usize,
    bytes: Vec<u8>,
    string_data_offsets: BTreeMap<String, u32>,
    proto_parameter_offsets: BTreeMap<ProtoRef, u32>,
    interface_offsets: BTreeMap<String, u32>,
    code_offsets: BTreeMap<MethodRef, u32>,
    class_data_offsets: BTreeMap<String, u32>,
}

impl<'a> DexWriter<'a> {
    fn new(classes: &'a [ClassSpec], tables: FixtureTables) -> Self {
        let string_ids_off = HEADER_SIZE;
        let type_ids_off = string_ids_off + tables.strings.len() * 4;
        let proto_ids_off = type_ids_off + tables.types.len() * 4;
        let field_ids_off = proto_ids_off + tables.protos.len() * 12;
        let method_ids_off = field_ids_off + tables.fields.len() * 8;
        let class_defs_off = method_ids_off + tables.methods.len() * 8;
        let data_off = align_to(class_defs_off + classes.len() * 32, 4);
        Self {
            classes,
            tables,
            string_ids_off,
            type_ids_off,
            proto_ids_off,
            field_ids_off,
            method_ids_off,
            class_defs_off,
            data_off,
            bytes: vec![0; data_off],
            string_data_offsets: BTreeMap::new(),
            proto_parameter_offsets: BTreeMap::new(),
            interface_offsets: BTreeMap::new(),
            code_offsets: BTreeMap::new(),
            class_data_offsets: BTreeMap::new(),
        }
    }

    fn write(mut self) -> Vec<u8> {
        self.write_string_data();
        self.write_type_lists();
        self.write_code_items();
        self.write_class_data();
        self.write_header();
        self.write_id_tables();
        self.write_class_defs();
        self.bytes
    }

    fn write_string_data(&mut self) {
        for value in &self.tables.strings {
            self.string_data_offsets
                .insert(value.clone(), self.bytes.len() as u32);
            write_uleb128(&mut self.bytes, value.chars().count() as u32);
            self.bytes.extend_from_slice(value.as_bytes());
            self.bytes.push(0);
        }
    }

    fn write_type_lists(&mut self) {
        let protos = self.tables.protos.clone();
        for proto in protos {
            if proto.parameters.is_empty() {
                self.proto_parameter_offsets.insert(proto, 0);
                continue;
            }
            align_vec(&mut self.bytes, 4);
            let offset = self.bytes.len() as u32;
            write_type_list(
                &mut self.bytes,
                &proto.parameters,
                &self.tables.type_indexes,
            );
            self.proto_parameter_offsets.insert(proto, offset);
        }

        for class in self.classes {
            if class.interfaces.is_empty() {
                self.interface_offsets.insert(class.descriptor.clone(), 0);
                continue;
            }
            align_vec(&mut self.bytes, 4);
            let offset = self.bytes.len() as u32;
            write_type_list(
                &mut self.bytes,
                &class.interfaces,
                &self.tables.type_indexes,
            );
            self.interface_offsets
                .insert(class.descriptor.clone(), offset);
        }
    }

    fn write_code_items(&mut self) {
        for class in self.classes {
            for method in &class.methods {
                if method.code.is_empty() {
                    continue;
                }
                align_vec(&mut self.bytes, 4);
                let offset = self.bytes.len() as u32;
                let mut code_units = encode_instructions(&method.code, &self.tables);
                code_units.push(0x000e);
                write_u16_vec(&mut self.bytes, &[4, 0, 4, 0]);
                self.bytes.extend_from_slice(&0u32.to_le_bytes());
                self.bytes
                    .extend_from_slice(&(code_units.len() as u32).to_le_bytes());
                write_u16_vec(&mut self.bytes, &code_units);
                self.code_offsets.insert(method.reference.clone(), offset);
            }
        }
    }

    fn write_class_data(&mut self) {
        for class in self.classes {
            let offset = self.bytes.len() as u32;
            let mut static_fields = class
                .fields
                .iter()
                .filter(|field| field.is_static)
                .collect::<Vec<_>>();
            let mut instance_fields = class
                .fields
                .iter()
                .filter(|field| !field.is_static)
                .collect::<Vec<_>>();
            let mut direct_methods = class
                .methods
                .iter()
                .filter(|method| matches!(method.kind, MethodKind::Direct | MethodKind::Static))
                .collect::<Vec<_>>();
            let mut virtual_methods = class
                .methods
                .iter()
                .filter(|method| {
                    matches!(
                        method.kind,
                        MethodKind::Virtual | MethodKind::AbstractVirtual
                    )
                })
                .collect::<Vec<_>>();

            sort_fields(&mut static_fields, &self.tables.field_indexes);
            sort_fields(&mut instance_fields, &self.tables.field_indexes);
            sort_methods(&mut direct_methods, &self.tables.method_indexes);
            sort_methods(&mut virtual_methods, &self.tables.method_indexes);

            write_uleb128(&mut self.bytes, static_fields.len() as u32);
            write_uleb128(&mut self.bytes, instance_fields.len() as u32);
            write_uleb128(&mut self.bytes, direct_methods.len() as u32);
            write_uleb128(&mut self.bytes, virtual_methods.len() as u32);
            write_encoded_fields(&mut self.bytes, &static_fields, &self.tables.field_indexes);
            write_encoded_fields(
                &mut self.bytes,
                &instance_fields,
                &self.tables.field_indexes,
            );
            write_encoded_methods(
                &mut self.bytes,
                &direct_methods,
                &self.tables.method_indexes,
                &self.code_offsets,
            );
            write_encoded_methods(
                &mut self.bytes,
                &virtual_methods,
                &self.tables.method_indexes,
                &self.code_offsets,
            );
            self.class_data_offsets
                .insert(class.descriptor.clone(), offset);
        }
    }

    fn write_header(&mut self) {
        let file_size = self.bytes.len();
        let data_size = file_size - self.data_off;
        self.bytes[0..8].copy_from_slice(b"dex\n035\0");
        write_u32(&mut self.bytes, 32, file_size as u32);
        write_u32(&mut self.bytes, 36, HEADER_SIZE as u32);
        write_u32(&mut self.bytes, 40, 0x12345678);
        write_table_header(
            &mut self.bytes,
            56,
            self.tables.strings.len(),
            self.string_ids_off,
        );
        write_table_header(
            &mut self.bytes,
            64,
            self.tables.types.len(),
            self.type_ids_off,
        );
        write_table_header(
            &mut self.bytes,
            72,
            self.tables.protos.len(),
            self.proto_ids_off,
        );
        write_table_header(
            &mut self.bytes,
            80,
            self.tables.fields.len(),
            self.field_ids_off,
        );
        write_table_header(
            &mut self.bytes,
            88,
            self.tables.methods.len(),
            self.method_ids_off,
        );
        write_table_header(&mut self.bytes, 96, self.classes.len(), self.class_defs_off);
        write_u32(&mut self.bytes, 104, data_size as u32);
        write_u32(&mut self.bytes, 108, self.data_off as u32);
    }

    fn write_id_tables(&mut self) {
        for (index, value) in self.tables.strings.iter().enumerate() {
            write_u32(
                &mut self.bytes,
                self.string_ids_off + index * 4,
                self.string_data_offsets[value],
            );
        }
        for (index, descriptor) in self.tables.types.iter().enumerate() {
            write_u32(
                &mut self.bytes,
                self.type_ids_off + index * 4,
                self.tables.string_indexes[descriptor],
            );
        }
        for (index, proto) in self.tables.protos.iter().enumerate() {
            let offset = self.proto_ids_off + index * 12;
            write_u32(
                &mut self.bytes,
                offset,
                self.tables.string_indexes[&shorty(proto)],
            );
            write_u32(
                &mut self.bytes,
                offset + 4,
                self.tables.type_indexes[&proto.return_type],
            );
            write_u32(
                &mut self.bytes,
                offset + 8,
                self.proto_parameter_offsets[proto],
            );
        }
        for (index, field) in self.tables.fields.iter().enumerate() {
            let offset = self.field_ids_off + index * 8;
            write_u16(
                &mut self.bytes,
                offset,
                self.tables.type_indexes[&field.owner] as u16,
            );
            write_u16(
                &mut self.bytes,
                offset + 2,
                self.tables.type_indexes[&field.field_type] as u16,
            );
            write_u32(
                &mut self.bytes,
                offset + 4,
                self.tables.string_indexes[&field.name],
            );
        }
        for (index, method) in self.tables.methods.iter().enumerate() {
            let offset = self.method_ids_off + index * 8;
            write_u16(
                &mut self.bytes,
                offset,
                self.tables.type_indexes[&method.owner] as u16,
            );
            write_u16(
                &mut self.bytes,
                offset + 2,
                self.tables.proto_indexes[&method.proto()] as u16,
            );
            write_u32(
                &mut self.bytes,
                offset + 4,
                self.tables.string_indexes[&method.name],
            );
        }
    }

    fn write_class_defs(&mut self) {
        for (index, class) in self.classes.iter().enumerate() {
            let offset = self.class_defs_off + index * 32;
            write_u32(
                &mut self.bytes,
                offset,
                self.tables.type_indexes[&class.descriptor],
            );
            let access_flags = if class.is_interface {
                ACC_PUBLIC | ACC_INTERFACE | ACC_ABSTRACT
            } else {
                ACC_PUBLIC
            };
            write_u32(&mut self.bytes, offset + 4, access_flags);
            write_u32(
                &mut self.bytes,
                offset + 8,
                class
                    .superclass
                    .as_ref()
                    .map(|superclass| self.tables.type_indexes[superclass])
                    .unwrap_or(u32::MAX),
            );
            write_u32(
                &mut self.bytes,
                offset + 12,
                self.interface_offsets[&class.descriptor],
            );
            write_u32(&mut self.bytes, offset + 16, u32::MAX);
            write_u32(&mut self.bytes, offset + 20, 0);
            write_u32(
                &mut self.bytes,
                offset + 24,
                self.class_data_offsets[&class.descriptor],
            );
            write_u32(&mut self.bytes, offset + 28, 0);
        }
    }
}

fn collect_instruction(
    instruction: &Instruction,
    strings: &mut BTreeSet<String>,
    types: &mut BTreeSet<String>,
    protos: &mut BTreeSet<ProtoRef>,
    fields: &mut BTreeSet<FieldRef>,
    methods: &mut BTreeSet<MethodRef>,
) {
    match instruction {
        Instruction::ConstClass(descriptor) => collect_type(descriptor, strings, types),
        Instruction::InvokeVirtual(method)
        | Instruction::InvokeDirect(method)
        | Instruction::InvokeStatic(method)
        | Instruction::InvokeInterface(method)
        | Instruction::InvokeInterfaceRange(method) => {
            collect_method(method, strings, types, protos, methods);
        }
        Instruction::ReadInstanceField(field) | Instruction::ReadStaticField(field) => {
            collect_field(field, strings, types, fields);
        }
    }
}

fn collect_method(
    method: &MethodRef,
    strings: &mut BTreeSet<String>,
    types: &mut BTreeSet<String>,
    protos: &mut BTreeSet<ProtoRef>,
    methods: &mut BTreeSet<MethodRef>,
) {
    collect_type(&method.owner, strings, types);
    collect_type(&method.return_type, strings, types);
    for parameter in &method.parameters {
        collect_type(parameter, strings, types);
    }
    strings.insert(method.name.clone());
    strings.insert(shorty(&method.proto()));
    protos.insert(method.proto());
    methods.insert(method.clone());
}

fn collect_field(
    field: &FieldRef,
    strings: &mut BTreeSet<String>,
    types: &mut BTreeSet<String>,
    fields: &mut BTreeSet<FieldRef>,
) {
    collect_type(&field.owner, strings, types);
    collect_type(&field.field_type, strings, types);
    strings.insert(field.name.clone());
    fields.insert(field.clone());
}

fn collect_type(descriptor: &str, strings: &mut BTreeSet<String>, types: &mut BTreeSet<String>) {
    strings.insert(descriptor.to_string());
    types.insert(descriptor.to_string());
}

fn shorty(proto: &ProtoRef) -> String {
    std::iter::once(shorty_character(&proto.return_type))
        .chain(proto.parameters.iter().map(|item| shorty_character(item)))
        .collect()
}

fn shorty_character(descriptor: &str) -> char {
    match descriptor.as_bytes().first().copied() {
        Some(b'L' | b'[') => 'L',
        Some(value) => value as char,
        None => 'V',
    }
}

fn index_values<T>(values: &[T]) -> BTreeMap<T, u32>
where
    T: Clone + Ord,
{
    values
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, value)| (value, index as u32))
        .collect()
}

fn encode_instructions(instructions: &[Instruction], tables: &FixtureTables) -> Vec<u16> {
    let mut code = Vec::new();
    for instruction in instructions {
        match instruction {
            Instruction::ConstClass(descriptor) => {
                code.extend([0x001c, tables.type_indexes[descriptor] as u16]);
            }
            Instruction::InvokeVirtual(method) => {
                code.extend([0x006e, tables.method_indexes[method] as u16, 0]);
            }
            Instruction::InvokeDirect(method) => {
                code.extend([0x0070, tables.method_indexes[method] as u16, 0]);
            }
            Instruction::InvokeStatic(method) => {
                code.extend([0x0071, tables.method_indexes[method] as u16, 0]);
            }
            Instruction::InvokeInterface(method) => {
                code.extend([0x0072, tables.method_indexes[method] as u16, 0]);
            }
            Instruction::InvokeInterfaceRange(method) => {
                code.extend([0x0078, tables.method_indexes[method] as u16, 0]);
            }
            Instruction::ReadInstanceField(field) => {
                code.extend([0x0052, tables.field_indexes[field] as u16]);
            }
            Instruction::ReadStaticField(field) => {
                code.extend([0x0060, tables.field_indexes[field] as u16]);
            }
        }
    }
    code
}

fn write_type_list(
    bytes: &mut Vec<u8>,
    descriptors: &[String],
    type_indexes: &BTreeMap<String, u32>,
) {
    bytes.extend_from_slice(&(descriptors.len() as u32).to_le_bytes());
    for descriptor in descriptors {
        bytes.extend_from_slice(&(type_indexes[descriptor] as u16).to_le_bytes());
    }
}

fn sort_fields(fields: &mut Vec<&FieldSpec>, indexes: &BTreeMap<FieldRef, u32>) {
    fields.sort_by_key(|field| indexes[&field.reference]);
}

fn sort_methods(methods: &mut Vec<&MethodSpec>, indexes: &BTreeMap<MethodRef, u32>) {
    methods.sort_by_key(|method| indexes[&method.reference]);
}

fn write_encoded_fields(
    bytes: &mut Vec<u8>,
    fields: &[&FieldSpec],
    indexes: &BTreeMap<FieldRef, u32>,
) {
    let mut previous = 0;
    for field in fields {
        let index = indexes[&field.reference];
        write_uleb128(bytes, index - previous);
        write_uleb128(
            bytes,
            if field.is_static {
                ACC_PUBLIC | ACC_STATIC
            } else {
                ACC_PUBLIC
            },
        );
        previous = index;
    }
}

fn write_encoded_methods(
    bytes: &mut Vec<u8>,
    methods: &[&MethodSpec],
    indexes: &BTreeMap<MethodRef, u32>,
    code_offsets: &BTreeMap<MethodRef, u32>,
) {
    let mut previous = 0;
    for method in methods {
        let index = indexes[&method.reference];
        write_uleb128(bytes, index - previous);
        let access_flags = match method.kind {
            MethodKind::Static => ACC_PUBLIC | ACC_STATIC,
            MethodKind::AbstractVirtual => ACC_PUBLIC | ACC_ABSTRACT,
            MethodKind::Direct | MethodKind::Virtual => ACC_PUBLIC,
        };
        write_uleb128(bytes, access_flags);
        write_uleb128(
            bytes,
            code_offsets.get(&method.reference).copied().unwrap_or(0),
        );
        previous = index;
    }
}

fn write_table_header(bytes: &mut [u8], offset: usize, size: usize, table_offset: usize) {
    write_u32(bytes, offset, size as u32);
    write_u32(
        bytes,
        offset + 4,
        if size == 0 { 0 } else { table_offset as u32 },
    );
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u16_vec(bytes: &mut Vec<u8>, values: &[u16]) {
    for value in values {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
}

fn write_uleb128(bytes: &mut Vec<u8>, mut value: u32) {
    loop {
        let mut current = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            current |= 0x80;
        }
        bytes.push(current);
        if value == 0 {
            break;
        }
    }
}

fn align_vec(bytes: &mut Vec<u8>, alignment: usize) {
    bytes.resize(align_to(bytes.len(), alignment), 0);
}

fn align_to(value: usize, alignment: usize) -> usize {
    value.div_ceil(alignment) * alignment
}
