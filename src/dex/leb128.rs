use crate::error::{Result, UnocRsError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Leb128 {
    pub value: u32,
    pub bytes_read: usize,
}

pub fn read_uleb128(bytes: &[u8], offset: usize) -> Result<Leb128> {
    let mut result = 0u32;
    let mut shift = 0u32;

    for index in 0..5 {
        let byte = *bytes
            .get(offset + index)
            .ok_or(UnocRsError::UnexpectedEof {
                offset: offset + index,
                needed: 1,
                len: bytes.len(),
            })?;
        result |= ((byte & 0x7f) as u32) << shift;

        if byte & 0x80 == 0 {
            return Ok(Leb128 {
                value: result,
                bytes_read: index + 1,
            });
        }

        shift += 7;
    }

    Err(UnocRsError::InvalidLeb128 { offset })
}

#[cfg(test)]
mod tests {
    use super::read_uleb128;

    #[test]
    fn reads_single_byte_uleb128() {
        let value = read_uleb128(&[0x7f], 0).expect("read");
        assert_eq!(value.value, 127);
        assert_eq!(value.bytes_read, 1);
    }

    #[test]
    fn reads_multi_byte_uleb128() {
        let value = read_uleb128(&[0xe5, 0x8e, 0x26], 0).expect("read");
        assert_eq!(value.value, 624_485);
        assert_eq!(value.bytes_read, 3);
    }

    #[test]
    fn rejects_overlong_uleb128() {
        let err = read_uleb128(&[0x80, 0x80, 0x80, 0x80, 0x80], 0).expect_err("error");
        assert!(err.to_string().contains("invalid LEB128"));
    }
}
