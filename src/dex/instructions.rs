use std::collections::BTreeMap;

use crate::error::{Result, UnocRsError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstructionReference {
    pub index: u32,
    pub offset_code_unit: u32,
    pub opcode: u8,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InstructionSummary {
    pub opcode_histogram: BTreeMap<u8, u32>,
    pub string_refs: Vec<u32>,
    pub method_refs: Vec<u32>,
    pub field_refs: Vec<u32>,
    pub type_ref_uses: Vec<InstructionReference>,
    pub method_ref_uses: Vec<InstructionReference>,
    pub field_ref_uses: Vec<InstructionReference>,
    pub branch_count: u32,
    pub return_count: u32,
    pub throw_count: u32,
    pub switch_count: u32,
    pub instruction_count: u32,
}

pub fn summarize_code_units(code_units: &[u16]) -> Result<InstructionSummary> {
    let mut summary = InstructionSummary::default();
    let mut cursor = 0usize;

    while cursor < code_units.len() {
        let first = code_units[cursor];
        let opcode = (first & 0x00ff) as u8;
        *summary.opcode_histogram.entry(opcode).or_insert(0) += 1;
        summary.instruction_count += 1;

        match opcode {
            0x1a => {
                if let Some(index) = code_units.get(cursor + 1) {
                    summary.string_refs.push(*index as u32);
                }
            }
            0x1b => {
                if cursor + 2 < code_units.len() {
                    let low = code_units[cursor + 1] as u32;
                    let high = code_units[cursor + 2] as u32;
                    summary.string_refs.push(low | (high << 16));
                }
            }
            0x1c | 0x1f | 0x20 | 0x22..=0x25 => {
                push_reference(&mut summary.type_ref_uses, code_units, cursor, opcode);
            }
            0x52..=0x6d => {
                push_reference(&mut summary.field_ref_uses, code_units, cursor, opcode);
            }
            0x6e..=0x72 | 0x74..=0x78 | 0xfa | 0xfb => {
                push_reference(&mut summary.method_ref_uses, code_units, cursor, opcode);
            }
            0x28..=0x2c => summary.branch_count += 1,
            0x0e..=0x11 => summary.return_count += 1,
            0x27 => summary.throw_count += 1,
            _ => {}
        }
        if matches!(opcode, 0x2b | 0x2c) {
            summary.switch_count += 1;
        }

        let width = opcode_width(code_units, cursor, opcode)?;
        cursor += width;
    }

    summary.method_refs = summary
        .method_ref_uses
        .iter()
        .map(|reference| reference.index)
        .collect();
    summary.field_refs = summary
        .field_ref_uses
        .iter()
        .map(|reference| reference.index)
        .collect();
    summary.string_refs.sort_unstable();
    summary.string_refs.dedup();
    summary.method_refs.sort_unstable();
    summary.method_refs.dedup();
    summary.field_refs.sort_unstable();
    summary.field_refs.dedup();
    Ok(summary)
}

fn push_reference(
    references: &mut Vec<InstructionReference>,
    code_units: &[u16],
    cursor: usize,
    opcode: u8,
) {
    let Some(index) = code_units.get(cursor + 1) else {
        return;
    };
    references.push(InstructionReference {
        index: *index as u32,
        offset_code_unit: cursor as u32,
        opcode,
    });
}

fn opcode_width(code_units: &[u16], cursor: usize, opcode: u8) -> Result<usize> {
    let width = match opcode {
        0x00 => {
            let high = (code_units[cursor] >> 8) as u8;
            match high {
                0x01 => 4 + payload_size(code_units, cursor)? * 2,
                0x02 => 2 + payload_size(code_units, cursor)? * 4,
                0x03 => fill_array_payload_width(code_units, cursor)?,
                _ => 1,
            }
        }
        0x01
        | 0x04
        | 0x07
        | 0x0a..=0x0d
        | 0x0e..=0x12
        | 0x1d
        | 0x1e
        | 0x21
        | 0x27
        | 0x28
        | 0x7b..=0x8f
        | 0xb0..=0xcf
        | 0xe3..=0xf9 => 1,
        0x02
        | 0x05
        | 0x08
        | 0x13
        | 0x15
        | 0x16
        | 0x19
        | 0x1a
        | 0x1c
        | 0x1f
        | 0x20
        | 0x22
        | 0x23
        | 0x29
        | 0x2d..=0x3d
        | 0x44..=0x51
        | 0x52..=0x6d
        | 0x90..=0xaf
        | 0xd0..=0xe2
        | 0xfe
        | 0xff => 2,
        0x03
        | 0x06
        | 0x09
        | 0x14
        | 0x17
        | 0x1b
        | 0x24..=0x26
        | 0x2a
        | 0x2b
        | 0x2c
        | 0x6e..=0x72
        | 0x74..=0x78
        | 0xfc
        | 0xfd => 3,
        0xfa | 0xfb => 4,
        0x18 => 5,
        0x73 | 0x79..=0x7a => 1,
        _ => 1,
    };

    if cursor + width <= code_units.len() {
        Ok(width)
    } else {
        Err(UnocRsError::InvalidInstruction {
            offset_code_unit: cursor,
            opcode,
        })
    }
}

fn payload_size(code_units: &[u16], cursor: usize) -> Result<usize> {
    code_units
        .get(cursor + 1)
        .copied()
        .map(usize::from)
        .ok_or(UnocRsError::InvalidInstruction {
            offset_code_unit: cursor,
            opcode: 0,
        })
}

fn fill_array_payload_width(code_units: &[u16], cursor: usize) -> Result<usize> {
    let element_width = code_units.get(cursor + 1).copied().map(usize::from).ok_or(
        UnocRsError::InvalidInstruction {
            offset_code_unit: cursor,
            opcode: 0,
        },
    )?;
    let element_count =
        read_code_unit_u32(code_units, cursor + 2).ok_or(UnocRsError::InvalidInstruction {
            offset_code_unit: cursor,
            opcode: 0,
        })? as usize;
    let data_bytes =
        element_width
            .checked_mul(element_count)
            .ok_or(UnocRsError::InvalidInstruction {
                offset_code_unit: cursor,
                opcode: 0,
            })?;
    Ok(4 + data_bytes.div_ceil(2))
}

fn read_code_unit_u32(code_units: &[u16], offset: usize) -> Option<u32> {
    let low = *code_units.get(offset)? as u32;
    let high = *code_units.get(offset + 1)? as u32;
    Some(low | (high << 16))
}

#[cfg(test)]
mod tests {
    use super::summarize_code_units;

    #[test]
    fn extracts_string_method_and_field_refs() {
        let code_units = [0x001a, 7, 0x006e, 11, 0, 0x0052, 13, 0x000e];
        let summary = summarize_code_units(&code_units).expect("summary");
        assert_eq!(summary.string_refs, vec![7]);
        assert_eq!(summary.method_refs, vec![11]);
        assert_eq!(summary.field_refs, vec![13]);
        assert_eq!(summary.return_count, 1);
    }

    #[test]
    fn records_reference_opcodes_and_offsets() {
        let code_units = [
            0x001c, 3, 0x0071, 5, 0, 0x0060, 7, 0x0018, 0, 0, 0, 0, 0x000e,
        ];
        let summary = summarize_code_units(&code_units).expect("summary");

        assert_eq!(summary.type_ref_uses[0].index, 3);
        assert_eq!(summary.type_ref_uses[0].offset_code_unit, 0);
        assert_eq!(summary.method_ref_uses[0].opcode, 0x71);
        assert_eq!(summary.method_ref_uses[0].offset_code_unit, 2);
        assert_eq!(summary.field_ref_uses[0].opcode, 0x60);
        assert_eq!(summary.field_ref_uses[0].offset_code_unit, 5);
        assert_eq!(summary.return_count, 1);
    }

    #[test]
    fn keeps_alignment_after_move_result_instructions() {
        let code_units = [0x0038, 8, 0x0071, 5, 0, 0x000c, 0x001a, 7, 0x0012, 0x000e];
        let summary = summarize_code_units(&code_units).expect("summary");

        assert_eq!(summary.method_ref_uses.len(), 1);
        assert_eq!(summary.method_ref_uses[0].offset_code_unit, 2);
        assert!(summary.field_ref_uses.is_empty());
        assert_eq!(summary.return_count, 1);
    }

    #[test]
    fn records_range_and_polymorphic_range_method_references() {
        let code_units = [0x0078, 11, 0, 0x00fb, 13, 0, 17, 0x000e];
        let summary = summarize_code_units(&code_units).expect("summary");

        assert_eq!(summary.method_ref_uses.len(), 2);
        assert_eq!(summary.method_ref_uses[0].index, 11);
        assert_eq!(summary.method_ref_uses[0].offset_code_unit, 0);
        assert_eq!(summary.method_ref_uses[1].index, 13);
        assert_eq!(summary.method_ref_uses[1].offset_code_unit, 3);
        assert_eq!(summary.return_count, 1);
    }

    #[test]
    fn skips_switch_and_array_payload_data() {
        let code_units = [0x0100, 1, 0, 0, 0, 0, 0x0300, 1, 2, 0, 0x1234, 0x000e];
        let summary = summarize_code_units(&code_units).expect("summary");

        assert_eq!(summary.instruction_count, 3);
        assert_eq!(summary.return_count, 1);
    }
}
