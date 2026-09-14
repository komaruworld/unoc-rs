use std::collections::BTreeMap;

use crate::error::{Result, UnocRsError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexHeader {
    pub version: String,
    pub file_size: u32,
    pub header_size: u32,
    pub endian_tag: u32,
    pub string_ids_size: u32,
    pub string_ids_off: u32,
    pub type_ids_size: u32,
    pub type_ids_off: u32,
    pub proto_ids_size: u32,
    pub proto_ids_off: u32,
    pub field_ids_size: u32,
    pub field_ids_off: u32,
    pub method_ids_size: u32,
    pub method_ids_off: u32,
    pub class_defs_size: u32,
    pub class_defs_off: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawDex {
    pub header: DexHeader,
    pub strings: Vec<String>,
    pub types: Vec<String>,
    pub protos: Vec<ProtoId>,
    pub fields: Vec<FieldId>,
    pub methods: Vec<MethodId>,
    pub classes: Vec<ClassDef>,
    pub code_items: BTreeMap<u32, CodeItem>,
    pub warnings: Vec<ParseWarning>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ParseWarning {
    pub origin: String,
    pub kind: ParseWarningKind,
    pub message: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum ParseWarningKind {
    DexSkipped,
    ClassData,
    CodeItem,
    Instruction,
    Reference,
}

impl RawDex {
    pub fn empty_for_test() -> Self {
        Self {
            header: DexHeader {
                version: "035".to_string(),
                file_size: 112,
                header_size: 112,
                endian_tag: 0x12345678,
                string_ids_size: 0,
                string_ids_off: 0,
                type_ids_size: 0,
                type_ids_off: 0,
                proto_ids_size: 0,
                proto_ids_off: 0,
                field_ids_size: 0,
                field_ids_off: 0,
                method_ids_size: 0,
                method_ids_off: 0,
                class_defs_size: 0,
                class_defs_off: 0,
            },
            strings: Vec::new(),
            types: Vec::new(),
            protos: Vec::new(),
            fields: Vec::new(),
            methods: Vec::new(),
            classes: Vec::new(),
            code_items: BTreeMap::new(),
            warnings: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtoId {
    pub shorty: String,
    pub return_type: String,
    pub parameters: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldId {
    pub class_type: String,
    pub field_type: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodId {
    pub class_type: String,
    pub name: String,
    pub proto: ProtoId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassDef {
    pub class_type: String,
    pub access_flags: u32,
    pub superclass: Option<String>,
    pub interfaces: Vec<String>,
    pub source_file: Option<String>,
    pub class_data_off: u32,
    pub class_data: Option<crate::dex::class_data::EncodedClassData>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeItem {
    pub registers_size: u16,
    pub ins_size: u16,
    pub outs_size: u16,
    pub tries_size: u16,
    pub debug_info_off: u32,
    pub insns_size: u32,
    pub instruction_summary: crate::dex::instructions::InstructionSummary,
}

pub fn parse_raw_dex(bytes: &[u8]) -> Result<RawDex> {
    let header = parse_header(bytes)?;
    let strings = parse_strings(bytes, &header)?;
    let types = parse_types(bytes, &header, &strings)?;
    let protos = parse_protos(bytes, &header, &strings, &types)?;
    let fields = parse_fields(bytes, &header, &strings, &types)?;
    let methods = parse_methods(bytes, &header, &strings, &types, &protos)?;
    let classes = parse_classes(bytes, &header, &strings, &types)?;
    let (code_items, warnings) = parse_code_items_for_classes(bytes, &classes);

    Ok(RawDex {
        header,
        strings,
        types,
        protos,
        fields,
        methods,
        classes,
        code_items,
        warnings,
    })
}

fn parse_header(bytes: &[u8]) -> Result<DexHeader> {
    let version = crate::dex::reader::read_dex_version(bytes)?;
    let header = DexHeader {
        version,
        file_size: crate::dex::reader::read_u32(bytes, 32)?,
        header_size: crate::dex::reader::read_u32(bytes, 36)?,
        endian_tag: crate::dex::reader::read_u32(bytes, 40)?,
        string_ids_size: crate::dex::reader::read_u32(bytes, 56)?,
        string_ids_off: crate::dex::reader::read_u32(bytes, 60)?,
        type_ids_size: crate::dex::reader::read_u32(bytes, 64)?,
        type_ids_off: crate::dex::reader::read_u32(bytes, 68)?,
        proto_ids_size: crate::dex::reader::read_u32(bytes, 72)?,
        proto_ids_off: crate::dex::reader::read_u32(bytes, 76)?,
        field_ids_size: crate::dex::reader::read_u32(bytes, 80)?,
        field_ids_off: crate::dex::reader::read_u32(bytes, 84)?,
        method_ids_size: crate::dex::reader::read_u32(bytes, 88)?,
        method_ids_off: crate::dex::reader::read_u32(bytes, 92)?,
        class_defs_size: crate::dex::reader::read_u32(bytes, 96)?,
        class_defs_off: crate::dex::reader::read_u32(bytes, 100)?,
    };

    if header.header_size != 112 {
        return Err(UnocRsError::InvalidDexHeader {
            reason: format!("header_size is {}, expected 112", header.header_size),
        });
    }
    if header.endian_tag != 0x12345678 {
        return Err(UnocRsError::InvalidDexHeader {
            reason: format!("unsupported endian tag 0x{:08x}", header.endian_tag),
        });
    }
    if header.file_size as usize > bytes.len() {
        return Err(UnocRsError::InvalidDexHeader {
            reason: format!(
                "file_size {} exceeds buffer length {}",
                header.file_size,
                bytes.len()
            ),
        });
    }

    Ok(header)
}

fn parse_strings(bytes: &[u8], header: &DexHeader) -> Result<Vec<String>> {
    let mut strings = Vec::with_capacity(header.string_ids_size as usize);
    for index in 0..header.string_ids_size {
        let id_off = table_offset(header.string_ids_off, index, 4);
        let string_data_off = crate::dex::reader::read_u32(bytes, id_off)? as usize;
        let len = crate::dex::leb128::read_uleb128(bytes, string_data_off)?;
        let start = string_data_off + len.bytes_read;
        let mut end = start;
        while end < bytes.len() && bytes[end] != 0 {
            end += 1;
        }
        let raw = crate::dex::reader::checked_slice(bytes, start, end - start)?;
        strings.push(String::from_utf8_lossy(raw).to_string());
    }
    Ok(strings)
}

fn parse_types(bytes: &[u8], header: &DexHeader, strings: &[String]) -> Result<Vec<String>> {
    let mut types = Vec::with_capacity(header.type_ids_size as usize);
    for index in 0..header.type_ids_size {
        let off = table_offset(header.type_ids_off, index, 4);
        let descriptor_idx = crate::dex::reader::read_u32(bytes, off)? as usize;
        let descriptor =
            strings
                .get(descriptor_idx)
                .ok_or_else(|| UnocRsError::InvalidDexHeader {
                    reason: format!("type descriptor index {descriptor_idx} is out of range"),
                })?;
        types.push(descriptor.clone());
    }
    Ok(types)
}

fn parse_protos(
    bytes: &[u8],
    header: &DexHeader,
    strings: &[String],
    types: &[String],
) -> Result<Vec<ProtoId>> {
    let mut protos = Vec::with_capacity(header.proto_ids_size as usize);
    for index in 0..header.proto_ids_size {
        let off = table_offset(header.proto_ids_off, index, 12);
        let shorty_idx = crate::dex::reader::read_u32(bytes, off)? as usize;
        let return_type_idx = crate::dex::reader::read_u32(bytes, off + 4)? as usize;
        let parameters_off = crate::dex::reader::read_u32(bytes, off + 8)?;
        let shorty = strings.get(shorty_idx).cloned().unwrap_or_default();
        let return_type = types.get(return_type_idx).cloned().unwrap_or_default();
        let parameters = parse_type_list(bytes, types, parameters_off)?;
        protos.push(ProtoId {
            shorty,
            return_type,
            parameters,
        });
    }
    Ok(protos)
}

fn parse_type_list(bytes: &[u8], types: &[String], offset: u32) -> Result<Vec<String>> {
    if offset == 0 {
        return Ok(Vec::new());
    }
    let size = crate::dex::reader::read_u32(bytes, offset as usize)?;
    let mut result = Vec::with_capacity(size as usize);
    let mut cursor = offset as usize + 4;
    for _ in 0..size {
        let type_idx = crate::dex::reader::read_u16(bytes, cursor)? as usize;
        cursor += 2;
        result.push(types.get(type_idx).cloned().unwrap_or_default());
    }
    Ok(result)
}

fn parse_fields(
    bytes: &[u8],
    header: &DexHeader,
    strings: &[String],
    types: &[String],
) -> Result<Vec<FieldId>> {
    let mut fields = Vec::with_capacity(header.field_ids_size as usize);
    for index in 0..header.field_ids_size {
        let off = table_offset(header.field_ids_off, index, 8);
        let class_idx = crate::dex::reader::read_u16(bytes, off)? as usize;
        let type_idx = crate::dex::reader::read_u16(bytes, off + 2)? as usize;
        let name_idx = crate::dex::reader::read_u32(bytes, off + 4)? as usize;
        fields.push(FieldId {
            class_type: types.get(class_idx).cloned().unwrap_or_default(),
            field_type: types.get(type_idx).cloned().unwrap_or_default(),
            name: strings.get(name_idx).cloned().unwrap_or_default(),
        });
    }
    Ok(fields)
}

fn parse_methods(
    bytes: &[u8],
    header: &DexHeader,
    strings: &[String],
    types: &[String],
    protos: &[ProtoId],
) -> Result<Vec<MethodId>> {
    let mut methods = Vec::with_capacity(header.method_ids_size as usize);
    for index in 0..header.method_ids_size {
        let off = table_offset(header.method_ids_off, index, 8);
        let class_idx = crate::dex::reader::read_u16(bytes, off)? as usize;
        let proto_idx = crate::dex::reader::read_u16(bytes, off + 2)? as usize;
        let name_idx = crate::dex::reader::read_u32(bytes, off + 4)? as usize;
        let proto = protos.get(proto_idx).cloned().unwrap_or(ProtoId {
            shorty: String::new(),
            return_type: String::new(),
            parameters: Vec::new(),
        });
        methods.push(MethodId {
            class_type: types.get(class_idx).cloned().unwrap_or_default(),
            name: strings.get(name_idx).cloned().unwrap_or_default(),
            proto,
        });
    }
    Ok(methods)
}

fn parse_classes(
    bytes: &[u8],
    header: &DexHeader,
    strings: &[String],
    types: &[String],
) -> Result<Vec<ClassDef>> {
    let mut classes = Vec::with_capacity(header.class_defs_size as usize);
    for index in 0..header.class_defs_size {
        let off = table_offset(header.class_defs_off, index, 32);
        let class_idx = crate::dex::reader::read_u32(bytes, off)? as usize;
        let access_flags = crate::dex::reader::read_u32(bytes, off + 4)?;
        let superclass_idx = crate::dex::reader::read_u32(bytes, off + 8)?;
        let interfaces_off = crate::dex::reader::read_u32(bytes, off + 12)?;
        let source_file_idx = crate::dex::reader::read_u32(bytes, off + 16)?;
        let class_data_off = crate::dex::reader::read_u32(bytes, off + 24)?;
        let class_data = if class_data_off == 0 {
            None
        } else {
            Some(crate::dex::class_data::parse_class_data(
                bytes,
                class_data_off,
            )?)
        };
        classes.push(ClassDef {
            class_type: types.get(class_idx).cloned().unwrap_or_default(),
            access_flags,
            superclass: optional_type(types, superclass_idx),
            interfaces: parse_type_list(bytes, types, interfaces_off)?,
            source_file: optional_string(strings, source_file_idx),
            class_data_off,
            class_data,
        });
    }
    Ok(classes)
}

fn parse_code_items_for_classes(
    bytes: &[u8],
    classes: &[ClassDef],
) -> (BTreeMap<u32, CodeItem>, Vec<ParseWarning>) {
    let mut code_items = BTreeMap::new();
    let mut warnings = Vec::new();

    for class in classes {
        let Some(class_data) = &class.class_data else {
            continue;
        };

        for method in class_data
            .direct_methods
            .iter()
            .chain(class_data.virtual_methods.iter())
        {
            if method.code_off == 0 || code_items.contains_key(&method.code_off) {
                continue;
            }

            match parse_code_item(bytes, method.code_off) {
                Ok(code_item) => {
                    code_items.insert(method.code_off, code_item);
                }
                Err(error) => warnings.push(ParseWarning {
                    origin: format!("{}@code_off={}", class.class_type, method.code_off),
                    kind: ParseWarningKind::CodeItem,
                    message: error.to_string(),
                }),
            }
        }
    }

    (code_items, warnings)
}

fn table_offset(base: u32, index: u32, width: u32) -> usize {
    (base + index * width) as usize
}

fn optional_string(strings: &[String], index: u32) -> Option<String> {
    if index == u32::MAX {
        None
    } else {
        strings.get(index as usize).cloned()
    }
}

fn optional_type(types: &[String], index: u32) -> Option<String> {
    if index == u32::MAX {
        None
    } else {
        types.get(index as usize).cloned()
    }
}

pub fn parse_code_item(bytes: &[u8], code_off: u32) -> Result<CodeItem> {
    let offset = code_off as usize;
    let registers_size = crate::dex::reader::read_u16(bytes, offset)?;
    let ins_size = crate::dex::reader::read_u16(bytes, offset + 2)?;
    let outs_size = crate::dex::reader::read_u16(bytes, offset + 4)?;
    let tries_size = crate::dex::reader::read_u16(bytes, offset + 6)?;
    let debug_info_off = crate::dex::reader::read_u32(bytes, offset + 8)?;
    let insns_size = crate::dex::reader::read_u32(bytes, offset + 12)?;
    let mut code_units = Vec::with_capacity(insns_size as usize);
    let mut cursor = offset + 16;
    for _ in 0..insns_size {
        code_units.push(crate::dex::reader::read_u16(bytes, cursor)?);
        cursor += 2;
    }
    let instruction_summary = crate::dex::instructions::summarize_code_units(&code_units)?;
    Ok(CodeItem {
        registers_size,
        ins_size,
        outs_size,
        tries_size,
        debug_info_off,
        insns_size,
        instruction_summary,
    })
}

#[cfg(test)]
mod tests {
    use super::parse_raw_dex;

    #[test]
    fn parses_empty_header() {
        let mut bytes = vec![0u8; 112];
        bytes[0..8].copy_from_slice(b"dex\n035\0");
        bytes[32..36].copy_from_slice(&112u32.to_le_bytes());
        bytes[36..40].copy_from_slice(&112u32.to_le_bytes());
        bytes[40..44].copy_from_slice(&0x12345678u32.to_le_bytes());
        bytes[52..56].copy_from_slice(&112u32.to_le_bytes());

        let raw = parse_raw_dex(&bytes).expect("parse");
        assert_eq!(raw.header.version, "035");
        assert_eq!(raw.header.file_size, 112);
        assert!(raw.strings.is_empty());
        assert!(raw.classes.is_empty());
    }

    #[test]
    fn rejects_bad_endian_tag() {
        let mut bytes = vec![0u8; 112];
        bytes[0..8].copy_from_slice(b"dex\n035\0");
        bytes[32..36].copy_from_slice(&112u32.to_le_bytes());
        bytes[36..40].copy_from_slice(&112u32.to_le_bytes());
        bytes[40..44].copy_from_slice(&0x78563412u32.to_le_bytes());

        let err = parse_raw_dex(&bytes).expect_err("bad endian");
        assert!(err.to_string().contains("unsupported endian tag"));
    }
}
