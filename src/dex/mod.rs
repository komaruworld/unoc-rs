pub mod class_data;
pub mod descriptor;
pub mod instructions;
pub mod leb128;
pub mod raw;
pub mod reader;

use crate::error::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDex {
    pub raw: raw::RawDex,
}

pub fn parse_dex(bytes: &[u8]) -> Result<ParsedDex> {
    Ok(ParsedDex {
        raw: raw::parse_raw_dex(bytes)?,
    })
}
