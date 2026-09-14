use crate::error::{Result, UnocRsError};

pub fn read_dex_version(bytes: &[u8]) -> Result<String> {
    let magic = checked_slice(bytes, 0, 8)?;
    if &magic[0..4] != b"dex\n" || magic[7] != 0 {
        return Err(UnocRsError::InvalidDexMagic);
    }
    let version = std::str::from_utf8(&magic[4..7])
        .map_err(|_| UnocRsError::InvalidDexMagic)?
        .to_string();
    match version.as_str() {
        "035" | "037" | "038" | "039" | "040" => Ok(version),
        _ => Err(UnocRsError::UnsupportedDexVersion(version)),
    }
}

pub fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let slice = checked_slice(bytes, offset, 2)?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

pub fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let slice = checked_slice(bytes, offset, 4)?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

pub fn checked_slice(bytes: &[u8], offset: usize, len: usize) -> Result<&[u8]> {
    let end = offset.checked_add(len).ok_or(UnocRsError::UnexpectedEof {
        offset,
        needed: len,
        len: bytes.len(),
    })?;
    bytes.get(offset..end).ok_or(UnocRsError::UnexpectedEof {
        offset,
        needed: len,
        len: bytes.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::{read_dex_version, read_u16, read_u32};

    #[test]
    fn reads_little_endian_values() {
        let bytes = [0x34, 0x12, 0x78, 0x56, 0x34, 0x12];
        assert_eq!(read_u16(&bytes, 0).expect("u16"), 0x1234);
        assert_eq!(read_u32(&bytes, 2).expect("u32"), 0x12345678);
    }

    #[test]
    fn accepts_supported_dex_magic() {
        assert_eq!(read_dex_version(b"dex\n035\0rest").expect("version"), "035");
        assert_eq!(read_dex_version(b"dex\n040\0rest").expect("version"), "040");
    }

    #[test]
    fn rejects_unsupported_dex_magic() {
        let err = read_dex_version(b"dex\n041\0rest").expect_err("unsupported");
        assert!(err.to_string().contains("unsupported DEX version"));
    }
}
