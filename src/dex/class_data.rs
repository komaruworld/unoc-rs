use crate::error::{Result, UnocRsError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedClassData {
    pub static_fields: Vec<EncodedField>,
    pub instance_fields: Vec<EncodedField>,
    pub direct_methods: Vec<EncodedMethod>,
    pub virtual_methods: Vec<EncodedMethod>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedField {
    pub field_idx: u32,
    pub access_flags: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedMethod {
    pub method_idx: u32,
    pub access_flags: u32,
    pub code_off: u32,
}

pub fn parse_class_data(bytes: &[u8], offset: u32) -> Result<EncodedClassData> {
    let mut cursor = offset as usize;
    let static_fields_size = read_next(bytes, &mut cursor)?;
    let instance_fields_size = read_next(bytes, &mut cursor)?;
    let direct_methods_size = read_next(bytes, &mut cursor)?;
    let virtual_methods_size = read_next(bytes, &mut cursor)?;

    let static_fields = read_fields(bytes, &mut cursor, static_fields_size)?;
    let instance_fields = read_fields(bytes, &mut cursor, instance_fields_size)?;
    let direct_methods = read_methods(bytes, &mut cursor, direct_methods_size)?;
    let virtual_methods = read_methods(bytes, &mut cursor, virtual_methods_size)?;

    Ok(EncodedClassData {
        static_fields,
        instance_fields,
        direct_methods,
        virtual_methods,
    })
}

fn read_next(bytes: &[u8], cursor: &mut usize) -> Result<u32> {
    let value = crate::dex::leb128::read_uleb128(bytes, *cursor)?;
    *cursor += value.bytes_read;
    Ok(value.value)
}

fn read_fields(bytes: &[u8], cursor: &mut usize, count: u32) -> Result<Vec<EncodedField>> {
    let mut fields = Vec::with_capacity(count as usize);
    let mut running_idx = 0u32;
    for _ in 0..count {
        running_idx = running_idx.checked_add(read_next(bytes, cursor)?).ok_or(
            UnocRsError::InvalidClassData {
                reason: "field index overflow".to_string(),
            },
        )?;
        let access_flags = read_next(bytes, cursor)?;
        fields.push(EncodedField {
            field_idx: running_idx,
            access_flags,
        });
    }
    Ok(fields)
}

fn read_methods(bytes: &[u8], cursor: &mut usize, count: u32) -> Result<Vec<EncodedMethod>> {
    let mut methods = Vec::with_capacity(count as usize);
    let mut running_idx = 0u32;
    for _ in 0..count {
        running_idx = running_idx.checked_add(read_next(bytes, cursor)?).ok_or(
            UnocRsError::InvalidClassData {
                reason: "method index overflow".to_string(),
            },
        )?;
        let access_flags = read_next(bytes, cursor)?;
        let code_off = read_next(bytes, cursor)?;
        methods.push(EncodedMethod {
            method_idx: running_idx,
            access_flags,
            code_off,
        });
    }
    Ok(methods)
}

#[cfg(test)]
mod tests {
    use super::parse_class_data;

    #[test]
    fn parses_delta_encoded_methods() {
        let bytes = [0x00, 0x00, 0x02, 0x00, 0x03, 0x01, 0x20, 0x02, 0x09, 0x21];
        let data = parse_class_data(&bytes, 0).expect("class data");
        assert_eq!(data.direct_methods.len(), 2);
        assert_eq!(data.direct_methods[0].method_idx, 3);
        assert_eq!(data.direct_methods[1].method_idx, 5);
        assert_eq!(data.direct_methods[1].access_flags, 9);
        assert_eq!(data.direct_methods[1].code_off, 33);
    }
}
