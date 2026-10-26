use super::*;

pub fn lower_to_ir(decoded: &[DecodedInstruction]) -> AppResult<Vec<IrInstruction>> {
    let mut ir = Vec::new();
    for instruction in decoded {
        match instruction.opcode {
            DecodedOpcode::Cpuid => ir.push(IrInstruction::Cpuid),
            DecodedOpcode::Xgetbv => ir.push(IrInstruction::Xgetbv),
            DecodedOpcode::MovImm => match instruction.operands.as_slice() {
                [Operand::Register(dst), Operand::ImmediateU64(value)] => {
                    ir.push(IrInstruction::MovImm {
                        dst: *dst,
                        value: *value,
                    });
                }
                [Operand::Register8(dst), Operand::ImmediateU64(value)] => {
                    ir.push(IrInstruction::MovImm8 {
                        dst: *dst,
                        value: *value as u8,
                    });
                }
                _ => {}
            },
            DecodedOpcode::MovReg => {
                if let [
                    Operand::Register(dst),
                    Operand::Register(src),
                    Operand::ImmediateU64(width),
                ] = instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::MovReg {
                        dst: *dst,
                        src: *src,
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::MovReg8 => {
                if let [Operand::Register8(dst), Operand::Register8(src), ..] =
                    instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::MovReg8 {
                        dst: *dst,
                        src: *src,
                    });
                }
            }
            DecodedOpcode::AddImm => match instruction.operands.as_slice() {
                [
                    Operand::Register(dst),
                    Operand::ImmediateU64(value),
                    Operand::ImmediateU64(width),
                ] => {
                    ir.push(IrInstruction::AddImm {
                        dst: *dst,
                        value: *value,
                        width: *width as usize,
                    });
                }
                [Operand::Register8(dst), Operand::ImmediateU64(value)] => {
                    ir.push(IrInstruction::AddImm8 {
                        dst: *dst,
                        value: *value as u8,
                    });
                }
                [
                    Operand::Memory(address),
                    Operand::ImmediateU64(value),
                    Operand::ImmediateU64(width),
                ] => {
                    ir.push(IrInstruction::AddImmMemory {
                        address: *address,
                        value: *value,
                        width: *width as usize,
                    });
                }
                _ => {}
            },
            DecodedOpcode::AdcImm => match instruction.operands.as_slice() {
                [
                    Operand::Register(dst),
                    Operand::ImmediateU64(value),
                    Operand::ImmediateU64(width),
                ] => {
                    ir.push(IrInstruction::AdcImm {
                        dst: *dst,
                        value: *value,
                        width: *width as usize,
                    });
                }
                [Operand::Register8(dst), Operand::ImmediateU64(value)] => {
                    ir.push(IrInstruction::AdcImm8 {
                        dst: *dst,
                        value: *value as u8,
                    });
                }
                [
                    Operand::Memory(address),
                    Operand::ImmediateU64(value),
                    Operand::ImmediateU64(width),
                ] => {
                    ir.push(IrInstruction::AdcImmMemory {
                        address: *address,
                        value: *value,
                        width: *width as usize,
                    });
                }
                _ => {}
            },
            DecodedOpcode::OrImm => match instruction.operands.as_slice() {
                [
                    Operand::Register(dst),
                    Operand::ImmediateU64(value),
                    Operand::ImmediateU64(width),
                ] => {
                    ir.push(IrInstruction::OrImm {
                        dst: *dst,
                        value: *value,
                        width: *width as usize,
                    });
                }
                [Operand::Register8(dst), Operand::ImmediateU64(value)] => {
                    ir.push(IrInstruction::OrImm8 {
                        dst: *dst,
                        value: *value as u8,
                    });
                }
                [
                    Operand::Memory(address),
                    Operand::ImmediateU64(value),
                    Operand::ImmediateU64(width),
                ] => {
                    ir.push(IrInstruction::OrImmMemory {
                        address: *address,
                        value: *value,
                        width: *width as usize,
                    });
                }
                _ => {}
            },
            DecodedOpcode::AddReg => match instruction.operands.as_slice() {
                [Operand::Register8(dst), Operand::Register8(src)] => {
                    ir.push(IrInstruction::AddReg8 {
                        dst: *dst,
                        src: *src,
                    });
                }
                [Operand::Register(dst), src, Operand::ImmediateU64(width)] => {
                    ir.push(IrInstruction::AddOperand {
                        dst: *dst,
                        src: compare_operand(src.clone()),
                        width: *width as usize,
                    });
                }
                [
                    Operand::Memory(address),
                    Operand::Register(src),
                    Operand::ImmediateU64(width),
                ] => {
                    ir.push(IrInstruction::AddMemory {
                        address: *address,
                        src: *src,
                        width: *width as usize,
                    });
                }
                _ => {}
            },
            DecodedOpcode::SubImm => match instruction.operands.as_slice() {
                [
                    Operand::Register(dst),
                    Operand::ImmediateU64(value),
                    Operand::ImmediateU64(width),
                ] => {
                    ir.push(IrInstruction::SubImm {
                        dst: *dst,
                        value: *value,
                        width: *width as usize,
                    });
                }
                [Operand::Register8(dst), Operand::ImmediateU64(value)] => {
                    ir.push(IrInstruction::SubImm8 {
                        dst: *dst,
                        value: *value as u8,
                    });
                }
                [
                    Operand::Memory(address),
                    Operand::ImmediateU64(value),
                    Operand::ImmediateU64(width),
                ] => {
                    ir.push(IrInstruction::SubImmMemory {
                        address: *address,
                        value: *value,
                        width: *width as usize,
                    });
                }
                _ => {}
            },
            DecodedOpcode::AndImm => match instruction.operands.as_slice() {
                [
                    Operand::Register(dst),
                    Operand::ImmediateU64(value),
                    Operand::ImmediateU64(width),
                ] => {
                    ir.push(IrInstruction::AndImm {
                        dst: *dst,
                        value: *value,
                        width: *width as usize,
                    });
                }
                [Operand::Register8(dst), Operand::ImmediateU64(value)] => {
                    ir.push(IrInstruction::AndImm8 {
                        dst: *dst,
                        value: *value as u8,
                    });
                }
                [
                    Operand::Memory(address),
                    Operand::ImmediateU64(value),
                    Operand::ImmediateU64(width),
                ] => {
                    ir.push(IrInstruction::AndImmMemory {
                        address: *address,
                        value: *value,
                        width: *width as usize,
                    });
                }
                _ => {}
            },
            DecodedOpcode::AndReg8 => match instruction.operands.as_slice() {
                [Operand::Register8(dst), Operand::Register8(src)] => {
                    ir.push(IrInstruction::AndReg8 {
                        dst: *dst,
                        src: *src,
                    });
                }
                [Operand::Register8(dst), src] => {
                    ir.push(IrInstruction::AndReg8Op {
                        dst: *dst,
                        src: compare_operand(src.clone()),
                    });
                }
                [Operand::Memory(address), Operand::Register8(src)] => {
                    ir.push(IrInstruction::AndMemory8 {
                        address: *address,
                        src: *src,
                    });
                }
                _ => {}
            },
            DecodedOpcode::AndReg => match instruction.operands.as_slice() {
                [Operand::Register(dst), src, Operand::ImmediateU64(width)] => {
                    ir.push(IrInstruction::AndReg {
                        dst: *dst,
                        src: compare_operand(src.clone()),
                        width: *width as usize,
                    });
                }
                [
                    Operand::Memory(address),
                    Operand::Register(src),
                    Operand::ImmediateU64(width),
                ] => {
                    ir.push(IrInstruction::AndMemory {
                        address: *address,
                        src: *src,
                        width: *width as usize,
                    });
                }
                _ => {}
            },
            DecodedOpcode::RolImm => match instruction.operands.as_slice() {
                [
                    Operand::Register(dst),
                    Operand::ImmediateU64(count),
                    Operand::ImmediateU64(width),
                ] => {
                    ir.push(IrInstruction::RolImm {
                        dst: *dst,
                        count: *count as u8,
                        width: *width as usize,
                    });
                }
                [
                    Operand::Memory(address),
                    Operand::ImmediateU64(count),
                    Operand::ImmediateU64(width),
                ] => {
                    ir.push(IrInstruction::RolImmMemory {
                        address: *address,
                        count: *count as u8,
                        width: *width as usize,
                    });
                }
                _ => {}
            },

            DecodedOpcode::RorImm => match instruction.operands.as_slice() {
                [
                    Operand::Register(dst),
                    Operand::ImmediateU64(count),
                    Operand::ImmediateU64(width),
                ] => {
                    ir.push(IrInstruction::RorImm {
                        dst: *dst,
                        count: *count as u8,
                        width: *width as usize,
                    });
                }
                [
                    Operand::Memory(address),
                    Operand::ImmediateU64(count),
                    Operand::ImmediateU64(width),
                ] => {
                    ir.push(IrInstruction::RorImmMemory {
                        address: *address,
                        count: *count as u8,
                        width: *width as usize,
                    });
                }
                _ => {}
            },
            DecodedOpcode::RclImm => match instruction.operands.as_slice() {
                [
                    Operand::Register(dst),
                    Operand::ImmediateU64(count),
                    Operand::ImmediateU64(width),
                ] => {
                    ir.push(IrInstruction::RclImm {
                        dst: *dst,
                        count: *count as u8,
                        width: *width as usize,
                    });
                }
                [
                    Operand::Memory(address),
                    Operand::ImmediateU64(count),
                    Operand::ImmediateU64(width),
                ] => {
                    ir.push(IrInstruction::RclImmMemory {
                        address: *address,
                        count: *count as u8,
                        width: *width as usize,
                    });
                }
                _ => {}
            },
            DecodedOpcode::RcrImm => match instruction.operands.as_slice() {
                [
                    Operand::Register(dst),
                    Operand::ImmediateU64(count),
                    Operand::ImmediateU64(width),
                ] => {
                    ir.push(IrInstruction::RcrImm {
                        dst: *dst,
                        count: *count as u8,
                        width: *width as usize,
                    });
                }
                [
                    Operand::Memory(address),
                    Operand::ImmediateU64(count),
                    Operand::ImmediateU64(width),
                ] => {
                    ir.push(IrInstruction::RcrImmMemory {
                        address: *address,
                        count: *count as u8,
                        width: *width as usize,
                    });
                }
                _ => {}
            },
            DecodedOpcode::BitTest => match instruction.operands.as_slice() {
                [
                    Operand::Register(base),
                    Operand::Register(bit),
                    Operand::ImmediateU64(width),
                ] => {
                    ir.push(IrInstruction::BitTest {
                        base: *base,
                        bit: *bit,
                        width: *width as usize,
                    });
                }
                [
                    src,
                    Operand::ImmediateU64(bit),
                    Operand::ImmediateU64(width),
                ] => {
                    ir.push(IrInstruction::BitTestImm {
                        src: compare_operand(src.clone()),
                        bit: *bit,
                        width: *width as usize,
                    });
                }
                _ => {}
            },
            DecodedOpcode::ShlImm => match instruction.operands.as_slice() {
                [
                    Operand::Register(dst),
                    Operand::ImmediateU64(count),
                    Operand::ImmediateU64(width),
                ] => {
                    ir.push(IrInstruction::ShlImm {
                        dst: *dst,
                        count: *count as u8,
                        width: *width as usize,
                    });
                }
                [
                    Operand::Memory(address),
                    Operand::ImmediateU64(count),
                    Operand::ImmediateU64(width),
                ] => {
                    ir.push(IrInstruction::ShlImmMemory {
                        address: *address,
                        count: *count as u8,
                        width: *width as usize,
                    });
                }
                _ => {}
            },
            DecodedOpcode::AdcReg => match instruction.operands.as_slice() {
                [Operand::Register8(dst), Operand::Register8(src)] => {
                    ir.push(IrInstruction::AdcReg8 {
                        dst: *dst,
                        src: *src,
                    });
                }
                [Operand::Register8(dst), src] => {
                    ir.push(IrInstruction::AdcReg8Op {
                        dst: *dst,
                        src: compare_operand(src.clone()),
                    });
                }
                [Operand::Register(dst), src, Operand::ImmediateU64(width)] => {
                    ir.push(IrInstruction::AdcOperand {
                        dst: *dst,
                        src: compare_operand(src.clone()),
                        width: *width as usize,
                    });
                }
                [
                    Operand::Memory(address),
                    Operand::Register(src),
                    Operand::ImmediateU64(width),
                ] => {
                    ir.push(IrInstruction::AdcMemory {
                        address: *address,
                        src: *src,
                        width: *width as usize,
                    });
                }
                [Operand::Memory(address), Operand::Register8(src)] => {
                    ir.push(IrInstruction::AdcMemory8 {
                        address: *address,
                        src: *src,
                    });
                }
                _ => {}
            },
            DecodedOpcode::ShrImm => match instruction.operands.as_slice() {
                [
                    Operand::Register(dst),
                    Operand::ImmediateU64(count),
                    Operand::ImmediateU64(width),
                ] => {
                    ir.push(IrInstruction::ShrImm {
                        dst: *dst,
                        count: *count as u8,
                        width: *width as usize,
                    });
                }
                [
                    Operand::Memory(address),
                    Operand::ImmediateU64(count),
                    Operand::ImmediateU64(width),
                ] => {
                    ir.push(IrInstruction::ShrImmMemory {
                        address: *address,
                        count: *count as u8,
                        width: *width as usize,
                    });
                }
                _ => {}
            },
            DecodedOpcode::SarImm => match instruction.operands.as_slice() {
                [
                    Operand::Register(dst),
                    Operand::ImmediateU64(count),
                    Operand::ImmediateU64(width),
                ] => {
                    ir.push(IrInstruction::SarImm {
                        dst: *dst,
                        count: *count as u8,
                        width: *width as usize,
                    });
                }
                [
                    Operand::Memory(address),
                    Operand::ImmediateU64(count),
                    Operand::ImmediateU64(width),
                ] => {
                    ir.push(IrInstruction::SarImmMemory {
                        address: *address,
                        count: *count as u8,
                        width: *width as usize,
                    });
                }
                _ => {}
            },
            DecodedOpcode::ShlCl => match instruction.operands.as_slice() {
                [Operand::Register(dst), Operand::ImmediateU64(width)] => {
                    ir.push(IrInstruction::ShlCl {
                        dst: *dst,
                        width: *width as usize,
                    });
                }
                [Operand::Memory(address), Operand::ImmediateU64(width)] => {
                    ir.push(IrInstruction::ShlClMemory {
                        address: *address,
                        width: *width as usize,
                    });
                }
                _ => {}
            },
            DecodedOpcode::RolCl => match instruction.operands.as_slice() {
                [Operand::Register(dst), Operand::ImmediateU64(width)] => {
                    ir.push(IrInstruction::RolCl {
                        dst: *dst,
                        width: *width as usize,
                    });
                }
                [Operand::Memory(address), Operand::ImmediateU64(width)] => {
                    ir.push(IrInstruction::RolClMemory {
                        address: *address,
                        width: *width as usize,
                    });
                }
                _ => {}
            },
            DecodedOpcode::RclCl => match instruction.operands.as_slice() {
                [Operand::Register(dst), Operand::ImmediateU64(width)] => {
                    ir.push(IrInstruction::RclCl {
                        dst: *dst,
                        width: *width as usize,
                    });
                }
                [Operand::Memory(address), Operand::ImmediateU64(width)] => {
                    ir.push(IrInstruction::RclClMemory {
                        address: *address,
                        width: *width as usize,
                    });
                }
                _ => {}
            },
            DecodedOpcode::RcrCl => match instruction.operands.as_slice() {
                [Operand::Register(dst), Operand::ImmediateU64(width)] => {
                    ir.push(IrInstruction::RcrCl {
                        dst: *dst,
                        width: *width as usize,
                    });
                }
                [Operand::Memory(address), Operand::ImmediateU64(width)] => {
                    ir.push(IrInstruction::RcrClMemory {
                        address: *address,
                        width: *width as usize,
                    });
                }
                _ => {}
            },
            DecodedOpcode::RorCl => match instruction.operands.as_slice() {
                [Operand::Register(dst), Operand::ImmediateU64(width)] => {
                    ir.push(IrInstruction::RorCl {
                        dst: *dst,
                        width: *width as usize,
                    });
                }
                [Operand::Memory(address), Operand::ImmediateU64(width)] => {
                    ir.push(IrInstruction::RorClMemory {
                        address: *address,
                        width: *width as usize,
                    });
                }
                _ => {}
            },
            DecodedOpcode::ShrCl => match instruction.operands.as_slice() {
                [Operand::Register(dst), Operand::ImmediateU64(width)] => {
                    ir.push(IrInstruction::ShrCl {
                        dst: *dst,
                        width: *width as usize,
                    });
                }
                [Operand::Memory(address), Operand::ImmediateU64(width)] => {
                    ir.push(IrInstruction::ShrClMemory {
                        address: *address,
                        width: *width as usize,
                    });
                }
                _ => {}
            },
            DecodedOpcode::SarCl => match instruction.operands.as_slice() {
                [Operand::Register(dst), Operand::ImmediateU64(width)] => {
                    ir.push(IrInstruction::SarCl {
                        dst: *dst,
                        width: *width as usize,
                    });
                }
                [Operand::Memory(address), Operand::ImmediateU64(width)] => {
                    ir.push(IrInstruction::SarClMemory {
                        address: *address,
                        width: *width as usize,
                    });
                }
                _ => {}
            },
            DecodedOpcode::ShldImm => {
                if let [
                    Operand::Register(dst),
                    Operand::Register(src),
                    Operand::ImmediateU64(count),
                    Operand::ImmediateU64(width),
                ] = instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::ShldImm {
                        dst: *dst,
                        src: *src,
                        count: *count as u8,
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::ShldCl => {
                if let [
                    Operand::Register(dst),
                    Operand::Register(src),
                    Operand::ImmediateU64(width),
                ] = instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::ShldCl {
                        dst: *dst,
                        src: *src,
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::ShrdImm => {
                if let [
                    Operand::Register(dst),
                    Operand::Register(src),
                    Operand::ImmediateU64(count),
                    Operand::ImmediateU64(width),
                ] = instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::ShrdImm {
                        dst: *dst,
                        src: *src,
                        count: *count as u8,
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::ImulImm => {
                if let [
                    Operand::Register(dst),
                    src,
                    Operand::ImmediateU64(imm),
                    Operand::ImmediateU64(width),
                ] = instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::ImulImm {
                        dst: *dst,
                        src: compare_operand(src.clone()),
                        imm: *imm,
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::ImulReg => {
                if let [Operand::Register(dst), src, Operand::ImmediateU64(width)] =
                    instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::ImulReg {
                        dst: *dst,
                        src: compare_operand(src.clone()),
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::MulAcc => {
                if let [src, Operand::ImmediateU64(width)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::MulAcc {
                        src: compare_operand(src.clone()),
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::ImulAcc => {
                if let [src, Operand::ImmediateU64(width)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::ImulAcc {
                        src: compare_operand(src.clone()),
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::Div => {
                if let [src, Operand::ImmediateU64(width)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::Div {
                        src: compare_operand(src.clone()),
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::Idiv => {
                if let [src, Operand::ImmediateU64(width)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::Idiv {
                        src: compare_operand(src.clone()),
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::SubReg8 => match instruction.operands.as_slice() {
                [Operand::Register8(dst), src] => {
                    ir.push(IrInstruction::SubReg8 {
                        dst: *dst,
                        src: compare_operand(src.clone()),
                    });
                }
                [Operand::Memory(address), Operand::Register8(src)] => {
                    ir.push(IrInstruction::SubMemory8 {
                        address: *address,
                        src: *src,
                    });
                }
                _ => {}
            },
            DecodedOpcode::Neg => match instruction.operands.as_slice() {
                [Operand::Register(dst), Operand::ImmediateU64(width)] => {
                    ir.push(IrInstruction::NegReg {
                        dst: *dst,
                        width: *width as usize,
                    });
                }
                [Operand::Register8(dst)] => {
                    ir.push(IrInstruction::NegReg8 { dst: *dst });
                }
                _ => {}
            },
            DecodedOpcode::Not => match instruction.operands.as_slice() {
                [Operand::Register(dst), Operand::ImmediateU64(width)] => {
                    ir.push(IrInstruction::NotReg {
                        dst: *dst,
                        width: *width as usize,
                    });
                }
                [Operand::Memory(address), Operand::ImmediateU64(width)] => {
                    ir.push(IrInstruction::NotMemory {
                        address: *address,
                        width: *width as usize,
                    });
                }
                [Operand::Register8(dst)] => {
                    ir.push(IrInstruction::NotReg8 { dst: *dst });
                }
                _ => {}
            },
            DecodedOpcode::Movs => {
                if let [Operand::ImmediateU64(width)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::Movs {
                        width: *width as usize,
                        repeat: instruction.prefixes.contains(&InstructionPrefix::Rep),
                    });
                }
            }
            DecodedOpcode::Stos => {
                if let [Operand::ImmediateU64(width)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::Stos {
                        width: *width as usize,
                        repeat: instruction.prefixes.contains(&InstructionPrefix::Rep),
                    });
                }
            }
            DecodedOpcode::Lods => {
                if let [Operand::ImmediateU64(width)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::Lods {
                        width: *width as usize,
                        repeat: instruction.prefixes.contains(&InstructionPrefix::Rep),
                    });
                }
            }
            DecodedOpcode::Cmps => {
                if let [Operand::ImmediateU64(width)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::Cmps {
                        width: *width as usize,
                        repeat: instruction.prefixes.contains(&InstructionPrefix::Rep),
                        repne: instruction.prefixes.contains(&InstructionPrefix::Repne),
                    });
                }
            }
            DecodedOpcode::Scas => {
                if let [Operand::ImmediateU64(width)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::Scas {
                        width: *width as usize,
                        repeat: instruction.prefixes.contains(&InstructionPrefix::Rep),
                        repne: instruction.prefixes.contains(&InstructionPrefix::Repne),
                    });
                }
            }
            DecodedOpcode::Bound => {
                if let [
                    Operand::Register(reg),
                    Operand::Memory(address),
                    Operand::ImmediateU64(width),
                ] = instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::Bound {
                        reg: *reg,
                        address: *address,
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::Hlt => ir.push(IrInstruction::Hlt),
            DecodedOpcode::Cli => ir.push(IrInstruction::Cli),
            DecodedOpcode::Sti => ir.push(IrInstruction::Sti),
            DecodedOpcode::Std => ir.push(IrInstruction::Std),
            DecodedOpcode::PortIn => {
                if let [Operand::ImmediateU64(width), Operand::ImmediateU64(port)] =
                    instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::PortIn {
                        port: Some(*port as u16),
                        width: *width as usize,
                    });
                } else if let [Operand::ImmediateU64(width)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::PortIn {
                        port: None,
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::PortOut => {
                if let [Operand::ImmediateU64(width), Operand::ImmediateU64(port)] =
                    instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::PortOut {
                        port: Some(*port as u16),
                        width: *width as usize,
                    });
                } else if let [Operand::ImmediateU64(width)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::PortOut {
                        port: None,
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::MovFromDr => {
                if let [Operand::Register(gpr), Operand::ImmediateU64(index)] =
                    instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::MovFromDr {
                        dst: *gpr,
                        index: *index as u8,
                    });
                }
            }
            DecodedOpcode::MovToDr => {
                if let [Operand::Register(gpr), Operand::ImmediateU64(index)] =
                    instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::MovToDr {
                        index: *index as u8,
                        src: *gpr,
                    });
                }
            }
            DecodedOpcode::Fxsave => {
                if let [Operand::Memory(address)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::Fxsave { address: *address });
                }
            }
            DecodedOpcode::Fxrstor => {
                if let [Operand::Memory(address)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::Fxrstor { address: *address });
                }
            }
            DecodedOpcode::Xsave => {
                if let [Operand::Memory(address)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::Xsave { address: *address });
                }
            }
            DecodedOpcode::Xsaveopt => {
                if let [Operand::Memory(address)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::Xsaveopt { address: *address });
                }
            }
            DecodedOpcode::Xrstor => {
                if let [Operand::Memory(address)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::Xrstor { address: *address });
                }
            }
            DecodedOpcode::Cdq => {
                if let [Operand::ImmediateU64(width)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::Cdq {
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::SubReg => match instruction.operands.as_slice() {
                [Operand::Register(dst), src, Operand::ImmediateU64(width)] => {
                    ir.push(IrInstruction::SubOperand {
                        dst: *dst,
                        src: compare_operand(src.clone()),
                        width: *width as usize,
                    });
                }
                [
                    Operand::Memory(address),
                    Operand::Register(src),
                    Operand::ImmediateU64(width),
                ] => {
                    ir.push(IrInstruction::SubMemory {
                        address: *address,
                        src: *src,
                        width: *width as usize,
                    });
                }
                _ => {}
            },
            DecodedOpcode::SbbReg => match instruction.operands.as_slice() {
                [Operand::Register(dst), src, Operand::ImmediateU64(width)] => {
                    ir.push(IrInstruction::SbbOperand {
                        dst: *dst,
                        src: compare_operand(src.clone()),
                        width: *width as usize,
                    });
                }
                [
                    Operand::Memory(address),
                    Operand::Register(src),
                    Operand::ImmediateU64(width),
                ] => {
                    ir.push(IrInstruction::SbbMemory {
                        address: *address,
                        src: *src,
                        width: *width as usize,
                    });
                }
                _ => {}
            },
            DecodedOpcode::SbbReg8 => match instruction.operands.as_slice() {
                [Operand::Register8(dst), src] => {
                    ir.push(IrInstruction::SbbReg8 {
                        dst: *dst,
                        src: compare_operand(src.clone()),
                    });
                }
                [Operand::Memory(address), Operand::Register8(src)] => {
                    ir.push(IrInstruction::SbbMemory8 {
                        address: *address,
                        src: *src,
                    });
                }
                _ => {}
            },
            DecodedOpcode::SbbImm => match instruction.operands.as_slice() {
                [Operand::Register8(dst), Operand::ImmediateU64(value)] => {
                    ir.push(IrInstruction::SbbImm8 {
                        dst: *dst,
                        value: *value as u8,
                    });
                }
                [
                    Operand::Register(dst),
                    Operand::ImmediateU64(value),
                    Operand::ImmediateU64(width),
                ] => {
                    ir.push(IrInstruction::SbbImm {
                        dst: *dst,
                        value: *value,
                        width: *width as usize,
                    });
                }
                _ => {}
            },
            DecodedOpcode::Cmp => {
                if let [lhs, rhs, Operand::ImmediateU64(width)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::Compare {
                        lhs: compare_operand(lhs.clone()),
                        rhs: compare_operand(rhs.clone()),
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::Test => {
                if let [lhs, rhs, Operand::ImmediateU64(width)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::Test {
                        lhs: compare_operand(lhs.clone()),
                        rhs: compare_operand(rhs.clone()),
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::Xchg => {
                match instruction.operands.as_slice() {
                    [
                        Operand::Memory(address),
                        Operand::Register8(reg),
                        Operand::ImmediateU64(_width),
                    ] => {
                        // XCHG r/m8, reg8 — exchange one byte, preserving the
                        // upper bits of the full register (AH/CH/DH/BH aware).
                        ir.push(IrInstruction::Mfence);
                        ir.push(IrInstruction::ExchangeMemory8 {
                            address: *address,
                            reg: *reg,
                        });
                    }
                    [
                        Operand::Register8(left),
                        Operand::Register8(right),
                        Operand::ImmediateU64(_width),
                    ] => {
                        ir.push(IrInstruction::ExchangeRegisters8 {
                            left: *left,
                            right: *right,
                        });
                    }
                    [
                        Operand::Memory(address),
                        Operand::Register(register),
                        Operand::ImmediateU64(width),
                    ] => {
                        // XCHG with memory has implicit LOCK semantics on x86.
                        // Emit a full memory barrier to match x86's stronger memory ordering.
                        ir.push(IrInstruction::Mfence);
                        ir.push(IrInstruction::ExchangeMemory {
                            address: *address,
                            register: *register,
                            width: *width as usize,
                        });
                    }
                    [
                        Operand::Register(left),
                        Operand::Register(right),
                        Operand::ImmediateU64(width),
                    ] => {
                        // If LOCK prefix is present on register/register XCHG, emit a memory barrier.
                        // The LOCK prefix on register XCHG acts as a full memory barrier on x86.
                        if instruction.prefixes.contains(&InstructionPrefix::Lock) {
                            ir.push(IrInstruction::Mfence);
                        }
                        ir.push(IrInstruction::ExchangeRegisters {
                            left: *left,
                            right: *right,
                            width: *width as usize,
                        });
                    }
                    _ => {}
                }
            }
            DecodedOpcode::Movsxd => {
                if let [Operand::Register(dst), src, Operand::ImmediateU64(width)] =
                    instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::SignExtendTo64 {
                        dst: *dst,
                        src: compare_operand(src.clone()),
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::Movsx => {
                if let [
                    Operand::Register(dst),
                    src,
                    Operand::ImmediateU64(src_width),
                    Operand::ImmediateU64(dst_width),
                ] = instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::SignExtend {
                        dst: *dst,
                        src: compare_operand(src.clone()),
                        src_width: *src_width as usize,
                        dst_width: *dst_width as usize,
                    });
                }
            }
            DecodedOpcode::Movzx => {
                if let [Operand::Register(dst), src, Operand::ImmediateU64(width)] =
                    instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::ZeroExtendTo64 {
                        dst: *dst,
                        src: compare_operand(src.clone()),
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::XorImm => match instruction.operands.as_slice() {
                [
                    Operand::Register(dst),
                    Operand::ImmediateU64(value),
                    Operand::ImmediateU64(width),
                ] => {
                    ir.push(IrInstruction::XorImm {
                        dst: *dst,
                        value: *value,
                        width: *width as usize,
                    });
                }
                [Operand::Register8(dst), Operand::ImmediateU64(value)] => {
                    ir.push(IrInstruction::XorImm8 {
                        dst: *dst,
                        value: *value as u8,
                    });
                }
                [
                    Operand::Memory(address),
                    Operand::ImmediateU64(value),
                    Operand::ImmediateU64(width),
                ] => {
                    ir.push(IrInstruction::XorImmMemory {
                        address: *address,
                        value: *value,
                        width: *width as usize,
                    });
                }
                _ => {}
            },
            DecodedOpcode::XorReg => match instruction.operands.as_slice() {
                [Operand::Register(dst), src, Operand::ImmediateU64(width)] => {
                    ir.push(IrInstruction::XorReg {
                        dst: *dst,
                        src: compare_operand(src.clone()),
                        width: *width as usize,
                    });
                }
                [
                    Operand::Memory(address),
                    Operand::Register(src),
                    Operand::ImmediateU64(width),
                ] => {
                    ir.push(IrInstruction::XorMemory {
                        address: *address,
                        src: *src,
                        width: *width as usize,
                    });
                }
                _ => {}
            },
            DecodedOpcode::XorReg8 => match instruction.operands.as_slice() {
                [Operand::Register8(dst), Operand::Register8(src)] => {
                    ir.push(IrInstruction::XorReg8 {
                        dst: *dst,
                        src: *src,
                    });
                }
                [Operand::Register8(dst), src] => {
                    ir.push(IrInstruction::XorReg8Op {
                        dst: *dst,
                        src: compare_operand(src.clone()),
                    });
                }
                [Operand::Memory(address), Operand::Register8(src)] => {
                    ir.push(IrInstruction::XorMemory8 {
                        address: *address,
                        src: *src,
                    });
                }
                _ => {}
            },
            DecodedOpcode::OrReg => match instruction.operands.as_slice() {
                [Operand::Register(dst), src, Operand::ImmediateU64(width)] => {
                    ir.push(IrInstruction::OrReg {
                        dst: *dst,
                        src: compare_operand(src.clone()),
                        width: *width as usize,
                    });
                }
                [
                    Operand::Memory(address),
                    Operand::Register(src),
                    Operand::ImmediateU64(width),
                ] => {
                    ir.push(IrInstruction::OrMemory {
                        address: *address,
                        src: *src,
                        width: *width as usize,
                    });
                }
                _ => {}
            },
            DecodedOpcode::OrReg8 => match instruction.operands.as_slice() {
                [Operand::Register8(dst), Operand::Register8(src)] => {
                    ir.push(IrInstruction::OrReg8 {
                        dst: *dst,
                        src: *src,
                    });
                }
                [Operand::Memory(address), Operand::Register8(src)] => {
                    ir.push(IrInstruction::OrMemory8 {
                        address: *address,
                        src: *src,
                    });
                }
                _ => {}
            },
            DecodedOpcode::IncReg => match instruction.operands.as_slice() {
                [Operand::Register(dst), Operand::ImmediateU64(width)] => {
                    ir.push(IrInstruction::IncReg {
                        dst: *dst,
                        width: *width as usize,
                    });
                }
                [Operand::Register8(dst), Operand::ImmediateU64(_)] => {
                    ir.push(IrInstruction::IncReg8 { dst: *dst });
                }
                [Operand::Memory(address), Operand::ImmediateU64(width)] => {
                    ir.push(IrInstruction::IncMemory {
                        address: *address,
                        width: *width as usize,
                    });
                }
                _ => {}
            },
            DecodedOpcode::DecReg => match instruction.operands.as_slice() {
                [Operand::Register(dst), Operand::ImmediateU64(width)] => {
                    ir.push(IrInstruction::DecReg {
                        dst: *dst,
                        width: *width as usize,
                    });
                }
                [Operand::Register8(dst), Operand::ImmediateU64(_)] => {
                    ir.push(IrInstruction::DecReg8 { dst: *dst });
                }
                [Operand::Memory(address), Operand::ImmediateU64(width)] => {
                    ir.push(IrInstruction::DecMemory {
                        address: *address,
                        width: *width as usize,
                    });
                }
                _ => {}
            },
            DecodedOpcode::Cmovcc => {
                if let [
                    Operand::ImmediateU64(condition),
                    Operand::Register(dst),
                    src,
                    Operand::ImmediateU64(width),
                ] = instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::Cmov {
                        condition: decode_condition(*condition)?,
                        dst: *dst,
                        src: compare_operand(src.clone()),
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::MovLoad => {
                if let [
                    Operand::Register(dst),
                    Operand::Memory(address),
                    Operand::ImmediateU64(width),
                ] = instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::LoadMemory {
                        dst: *dst,
                        address: *address,
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::MovLoad8 => {
                if let [
                    Operand::Register8(dst),
                    Operand::Memory(address),
                    Operand::ImmediateU64(_width),
                ] = instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::LoadMemory8 {
                        dst: *dst,
                        address: *address,
                    });
                }
            }
            DecodedOpcode::MovStore => {
                if let [
                    Operand::Memory(address),
                    Operand::Register(src),
                    Operand::ImmediateU64(width),
                ] = instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::StoreMemory {
                        src: *src,
                        address: *address,
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::MovStore8 => {
                if let [
                    Operand::Memory(address),
                    Operand::Register8(src),
                    Operand::ImmediateU64(_width),
                ] = instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::StoreMemory8 {
                        src: *src,
                        address: *address,
                    });
                }
            }
            DecodedOpcode::MovStoreImm => {
                if let [
                    Operand::Memory(address),
                    Operand::ImmediateU64(value),
                    Operand::ImmediateU64(width),
                ] = instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::StoreImmediate {
                        address: *address,
                        value: *value,
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::Nop => ir.push(IrInstruction::Nop),
            DecodedOpcode::Int3 => ir.push(IrInstruction::Breakpoint),
            DecodedOpcode::Int { vector: 0x03 } | DecodedOpcode::Int { vector: 0x2d } => {
                // int 0x03 (DEBUG_INT) and int 0x2d (debug break) both act as
                // breakpoints in modern Windows (STATUS_BREAKPOINT).
                ir.push(IrInstruction::Breakpoint);
            }
            DecodedOpcode::Int { .. } => {
                // Other software interrupt vectors are currently treated as NOPs
                // (most games do not rely on arbitrary INT instructions).
                ir.push(IrInstruction::Nop);
            }
            DecodedOpcode::PushSeg => {
                if let [Operand::ImmediateU64(width)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::PushImm {
                        value: 0,
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::PopSeg => {
                if let [Operand::ImmediateU64(width)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::PopSeg {
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::Loop => ir.push(IrInstruction::Nop),
            DecodedOpcode::CallRel => {
                if let [
                    Operand::ImmediateU64(target),
                    Operand::ImmediateU64(return_address),
                ] = instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::Call {
                        target: *target,
                        return_address: *return_address,
                    });
                }
            }
            DecodedOpcode::CallRegister => {
                if let [
                    Operand::Register(src),
                    Operand::ImmediateU64(return_address),
                ] = instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::CallRegister {
                        src: *src,
                        return_address: *return_address,
                    });
                }
            }
            DecodedOpcode::CallMemory => {
                if let [
                    Operand::Memory(address),
                    Operand::ImmediateU64(return_address),
                ] = instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::CallMemory {
                        address: *address,
                        return_address: *return_address,
                    });
                }
            }
            DecodedOpcode::JmpRegister => {
                if let [Operand::Register(src)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::JumpRegister { src: *src });
                }
            }
            DecodedOpcode::JmpMemory => {
                if let [Operand::Memory(address)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::JumpMemory { address: *address });
                }
            }
            DecodedOpcode::Setcc => {
                if let [Operand::ImmediateU64(condition), dst] = instruction.operands.as_slice() {
                    let condition = decode_condition(*condition)?;
                    match dst {
                        Operand::Register8(dst) => ir.push(IrInstruction::Setcc {
                            condition,
                            dst: *dst,
                        }),
                        Operand::Memory(address) => ir.push(IrInstruction::SetccMemory {
                            condition,
                            address: *address,
                        }),
                        _ => {}
                    }
                }
            }
            DecodedOpcode::Ldmxcsr => {
                if let [Operand::Memory(address)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::LoadMxcsr { address: *address });
                }
            }
            DecodedOpcode::Stmxcsr => {
                if let [Operand::Memory(address)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::StoreMxcsr { address: *address });
                }
            }
            DecodedOpcode::Jcc => {
                if let [
                    Operand::ImmediateU64(condition),
                    Operand::ImmediateU64(target),
                    Operand::ImmediateU64(fallthrough),
                ] = instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::JumpIf {
                        condition: decode_condition(*condition)?,
                        target: *target,
                        fallthrough: *fallthrough,
                    });
                }
            }
            DecodedOpcode::JmpRel => {
                if let [Operand::ImmediateU64(target)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::Jump { target: *target });
                }
            }
            DecodedOpcode::Lea => {
                if let [
                    Operand::Register(dst),
                    Operand::Memory(address),
                    Operand::ImmediateU64(width),
                ] = instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::LoadEffectiveAddress {
                        dst: *dst,
                        address: *address,
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::PushReg => {
                if let [Operand::Register(src)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::PushReg { src: *src });
                }
            }
            DecodedOpcode::PushAll => ir.push(IrInstruction::PushAll),
            DecodedOpcode::PopAll => ir.push(IrInstruction::PopAll),
            DecodedOpcode::PushMemory => {
                if let [Operand::Memory(address), Operand::ImmediateU64(width)] =
                    instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::PushMemory {
                        address: *address,
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::PushImm => {
                if let [Operand::ImmediateU64(value), Operand::ImmediateU64(width)] =
                    instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::PushImm {
                        value: *value,
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::PushFlags => {
                if let [Operand::ImmediateU64(width)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::PushFlags {
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::PopReg => {
                if let [Operand::Register(dst)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::PopReg { dst: *dst });
                }
            }
            DecodedOpcode::PopMemory => {
                if let [Operand::Memory(address), Operand::ImmediateU64(width)] =
                    instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::PopMemory {
                        address: *address,
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::PopFlags => {
                if let [Operand::ImmediateU64(width)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::PopFlags {
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::Sahf => ir.push(IrInstruction::Sahf),
            DecodedOpcode::Lahf => ir.push(IrInstruction::Lahf),
            DecodedOpcode::SetCarryFlag { value } => {
                ir.push(IrInstruction::SetCarryFlag { value });
            }
            DecodedOpcode::Cmc => ir.push(IrInstruction::ComplementCarryFlag),
            DecodedOpcode::LoadSegment { segment } => {
                if let [src] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::LoadSegment {
                        segment,
                        src: compare_operand(src.clone()),
                    });
                }
            }
            DecodedOpcode::Cld => ir.push(IrInstruction::Cld),
            DecodedOpcode::Leave => ir.push(IrInstruction::Leave),
            DecodedOpcode::Ret => {
                let stack_adjust = match instruction.operands.as_slice() {
                    [] => 0,
                    [Operand::ImmediateU64(stack_adjust)] => *stack_adjust,
                    _ => 0,
                };
                ir.push(IrInstruction::Return { stack_adjust });
            }
            DecodedOpcode::Popcnt => {
                if let [Operand::Register(dst), Operand::Register(src)] =
                    instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::Popcnt {
                        dst: *dst,
                        src: *src,
                    });
                }
            }
            DecodedOpcode::Lzcnt => {
                if let [Operand::Register(dst), Operand::Register(src)] =
                    instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::Lzcnt {
                        dst: *dst,
                        src: *src,
                    });
                }
            }
            DecodedOpcode::Bsf => {
                if let [Operand::Register(dst), Operand::Register(src)] =
                    instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::Bsf {
                        dst: *dst,
                        src: *src,
                    });
                }
            }
            DecodedOpcode::Bswap => {
                if let [Operand::Register(dst), Operand::ImmediateU64(width)] =
                    instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::Bswap {
                        dst: *dst,
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::Ud2 => ir.push(IrInstruction::Ud2),
            DecodedOpcode::MovdToXmm => {
                if let [Operand::Xmm(dst), Operand::Register(src)] = instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::MovdToXmm {
                        dst: *dst,
                        src: *src,
                    });
                }
            }
            DecodedOpcode::MovdFromXmm => match instruction.operands.as_slice() {
                [Operand::Register(dst), Operand::Xmm(src)] => {
                    ir.push(IrInstruction::MovdFromXmm {
                        dst: *dst,
                        src: *src,
                    });
                }
                [Operand::Memory(address), Operand::Xmm(src)] => {
                    ir.push(IrInstruction::StoreDwordFromXmm {
                        address: *address,
                        src: *src,
                    });
                }
                _ => {}
            },
            DecodedOpcode::Pshufd => {
                if let [
                    Operand::Xmm(dst),
                    Operand::Xmm(src),
                    Operand::ImmediateU64(imm),
                ] = instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::Pshufd {
                        dst: *dst,
                        src: *src,
                        imm: *imm as u8,
                    });
                }
            }
            DecodedOpcode::Pshuflw => {
                if let [
                    Operand::Xmm(dst),
                    Operand::Xmm(src),
                    Operand::ImmediateU64(imm),
                ] = instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::Pshuflw {
                        dst: *dst,
                        src: *src,
                        imm: *imm as u8,
                    });
                }
            }
            DecodedOpcode::Psrldq => {
                if let [Operand::Xmm(dst), Operand::ImmediateU64(imm)] =
                    instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::Psrldq {
                        dst: *dst,
                        imm: *imm as u8,
                    });
                }
            }
            DecodedOpcode::Pslldq => {
                if let [Operand::Xmm(dst), Operand::ImmediateU64(imm)] =
                    instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::Pslldq {
                        dst: *dst,
                        imm: *imm as u8,
                    });
                }
            }
            DecodedOpcode::Movlhps => {
                if let [Operand::Xmm(dst), Operand::Xmm(src)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::Movlhps {
                        dst: *dst,
                        src: *src,
                    });
                }
            }
            DecodedOpcode::XmmMove => match instruction.operands.as_slice() {
                [Operand::Xmm(dst), Operand::Xmm(src)] => {
                    ir.push(IrInstruction::MoveXmm {
                        dst: *dst,
                        src: *src,
                    });
                }
                [Operand::Xmm(dst), Operand::Memory(address)] => {
                    ir.push(IrInstruction::LoadXmm {
                        dst: *dst,
                        address: *address,
                    });
                }
                [Operand::Memory(address), Operand::Xmm(src)] => {
                    ir.push(IrInstruction::StoreXmm {
                        src: *src,
                        address: *address,
                    });
                }
                _ => {}
            },
            DecodedOpcode::VectorMove => match instruction.operands.as_slice() {
                [
                    Operand::Xmm(dst),
                    Operand::Xmm(src),
                    Operand::ImmediateU64(width),
                ] => {
                    ir.push(IrInstruction::MoveVector {
                        dst: *dst,
                        src: *src,
                        width: *width as usize,
                    });
                }
                [
                    Operand::Xmm(dst),
                    Operand::Memory(address),
                    Operand::ImmediateU64(width),
                ] => {
                    ir.push(IrInstruction::LoadVector {
                        dst: *dst,
                        address: *address,
                        width: *width as usize,
                    });
                }
                [
                    Operand::Memory(address),
                    Operand::Xmm(src),
                    Operand::ImmediateU64(width),
                ] => {
                    ir.push(IrInstruction::StoreVector {
                        src: *src,
                        address: *address,
                        width: *width as usize,
                    });
                }
                _ => {}
            },
            DecodedOpcode::Pxor => {
                if let [Operand::Xmm(dst), Operand::Xmm(src)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::Pxor {
                        dst: *dst,
                        src: *src,
                    });
                }
            }
            DecodedOpcode::VectorOr => {
                if let [
                    Operand::Xmm(dst),
                    Operand::Xmm(lhs),
                    rhs,
                    Operand::ImmediateU64(width),
                ] = instruction.operands.as_slice()
                {
                    let rhs = match rhs {
                        Operand::Xmm(src) => Some(VectorOperand::Register(*src)),
                        Operand::Memory(address) => Some(VectorOperand::Memory(*address)),
                        _ => None,
                    };
                    if let Some(rhs) = rhs {
                        ir.push(IrInstruction::VectorOr {
                            dst: *dst,
                            lhs: *lhs,
                            rhs,
                            width: *width as usize,
                        });
                    }
                }
            }
            DecodedOpcode::VectorXor => {
                if let [
                    Operand::Xmm(dst),
                    Operand::Xmm(lhs),
                    rhs,
                    Operand::ImmediateU64(width),
                ] = instruction.operands.as_slice()
                {
                    let rhs = match rhs {
                        Operand::Xmm(src) => Some(VectorOperand::Register(*src)),
                        Operand::Memory(address) => Some(VectorOperand::Memory(*address)),
                        _ => None,
                    };
                    if let Some(rhs) = rhs {
                        ir.push(IrInstruction::VectorXor {
                            dst: *dst,
                            lhs: *lhs,
                            rhs,
                            width: *width as usize,
                        });
                    }
                }
            }
            DecodedOpcode::VectorAnd => {
                if let [
                    Operand::Xmm(dst),
                    Operand::Xmm(lhs),
                    rhs,
                    Operand::ImmediateU64(width),
                ] = instruction.operands.as_slice()
                {
                    let rhs = match rhs {
                        Operand::Xmm(src) => Some(VectorOperand::Register(*src)),
                        Operand::Memory(address) => Some(VectorOperand::Memory(*address)),
                        _ => None,
                    };
                    if let Some(rhs) = rhs {
                        ir.push(IrInstruction::VectorAnd {
                            dst: *dst,
                            lhs: *lhs,
                            rhs,
                            width: *width as usize,
                        });
                    }
                }
            }
            DecodedOpcode::VectorAndNot => {
                if let [
                    Operand::Xmm(dst),
                    Operand::Xmm(lhs),
                    rhs,
                    Operand::ImmediateU64(width),
                ] = instruction.operands.as_slice()
                {
                    let rhs = match rhs {
                        Operand::Xmm(src) => Some(VectorOperand::Register(*src)),
                        Operand::Memory(address) => Some(VectorOperand::Memory(*address)),
                        _ => None,
                    };
                    if let Some(rhs) = rhs {
                        ir.push(IrInstruction::VectorAndNot {
                            dst: *dst,
                            lhs: *lhs,
                            rhs,
                            width: *width as usize,
                        });
                    }
                }
            }
            DecodedOpcode::VectorIntOp { kind } => {
                if let [
                    Operand::Xmm(dst),
                    Operand::Xmm(lhs),
                    rhs,
                    Operand::ImmediateU64(width),
                ] = instruction.operands.as_slice()
                {
                    let rhs = match rhs {
                        Operand::Xmm(src) => Some(VectorOperand::Register(*src)),
                        Operand::Memory(address) => Some(VectorOperand::Memory(*address)),
                        _ => None,
                    };
                    if let Some(rhs) = rhs {
                        ir.push(IrInstruction::VectorIntOp {
                            kind,
                            dst: *dst,
                            lhs: *lhs,
                            rhs,
                            width: *width as usize,
                        });
                    }
                }
            }
            DecodedOpcode::Paddq => {
                if let [Operand::Xmm(dst), Operand::Xmm(src)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::Paddq {
                        dst: *dst,
                        src: *src,
                    });
                }
            }
            DecodedOpcode::Paddd => {
                if let [Operand::Xmm(dst), Operand::Xmm(src)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::Paddd {
                        dst: *dst,
                        src: *src,
                    });
                }
            }
            DecodedOpcode::Pmulld => {
                if let [Operand::Xmm(dst), Operand::Xmm(src)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::Pmulld {
                        dst: *dst,
                        src: *src,
                    });
                }
            }
            DecodedOpcode::Psubd => {
                if let [Operand::Xmm(dst), Operand::Xmm(src)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::Psubd {
                        dst: *dst,
                        src: *src,
                    });
                }
            }
            DecodedOpcode::VectorAddQ => {
                if let [
                    Operand::Xmm(dst),
                    Operand::Xmm(lhs),
                    rhs,
                    Operand::ImmediateU64(width),
                ] = instruction.operands.as_slice()
                {
                    let rhs = match rhs {
                        Operand::Xmm(src) => Some(VectorOperand::Register(*src)),
                        Operand::Memory(address) => Some(VectorOperand::Memory(*address)),
                        _ => None,
                    };
                    if let Some(rhs) = rhs {
                        ir.push(IrInstruction::VectorAddQ {
                            dst: *dst,
                            lhs: *lhs,
                            rhs,
                            width: *width as usize,
                        });
                    }
                }
            }
            DecodedOpcode::VzeroUpper => ir.push(IrInstruction::VzeroUpper),
            DecodedOpcode::VectorCompareEqBytes => {
                if let [
                    Operand::Xmm(dst),
                    Operand::Xmm(lhs),
                    rhs,
                    Operand::ImmediateU64(width),
                ] = instruction.operands.as_slice()
                {
                    let rhs = match rhs {
                        Operand::Xmm(src) => Some(VectorOperand::Register(*src)),
                        Operand::Memory(address) => Some(VectorOperand::Memory(*address)),
                        _ => None,
                    };
                    if let Some(rhs) = rhs {
                        ir.push(IrInstruction::VectorCompareEqBytes {
                            dst: *dst,
                            lhs: *lhs,
                            rhs,
                            width: *width as usize,
                        });
                    }
                }
            }
            DecodedOpcode::VectorMoveMaskBytes => {
                if let [
                    Operand::Register(dst),
                    Operand::Xmm(src),
                    Operand::ImmediateU64(width),
                ] = instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::VectorMoveMaskBytes {
                        dst: *dst,
                        src: *src,
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::Fnclex => ir.push(IrInstruction::X87ClearExceptions),
            DecodedOpcode::FldConst => {
                if let [Operand::ImmediateU64(bits)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::X87LoadConst {
                        value: f64::from_bits(*bits),
                    });
                }
            }
            DecodedOpcode::FildI32 => {
                if let [Operand::Memory(address)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::X87LoadInt32 { address: *address });
                }
            }
            DecodedOpcode::FildI64 => {
                if let [Operand::Memory(address)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::X87LoadInt64 { address: *address });
                }
            }
            DecodedOpcode::Fchs => ir.push(IrInstruction::X87NegateTop),
            DecodedOpcode::FldReal32 => {
                if let [Operand::Memory(address)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::X87Load {
                        address: *address,
                        width: 4,
                    });
                }
            }
            DecodedOpcode::FldReal64 => {
                if let [Operand::Memory(address)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::X87Load {
                        address: *address,
                        width: 8,
                    });
                }
            }
            DecodedOpcode::Fldcw => {
                if let [Operand::Memory(address)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::X87LoadControlWord { address: *address });
                }
            }
            DecodedOpcode::FdivReal64 => {
                if let [Operand::Memory(address)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::X87DivMemory {
                        address: *address,
                        width: 8,
                    });
                }
            }
            DecodedOpcode::FaddReal64 => {
                if let [Operand::Memory(address)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::X87AddMemory {
                        address: *address,
                        width: 8,
                    });
                }
            }
            DecodedOpcode::Fxch => {
                if let [Operand::ImmediateU64(index)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::X87Swap {
                        index: *index as usize,
                    });
                }
            }
            DecodedOpcode::Cvtpd2ps => {
                if let [Operand::Xmm(dst), src] = instruction.operands.as_slice() {
                    let src = match src {
                        Operand::Xmm(src) => Some(VectorOperand::Register(*src)),
                        Operand::Memory(address) => Some(VectorOperand::Memory(*address)),
                        _ => None,
                    };
                    if let Some(src) = src {
                        ir.push(IrInstruction::Cvtpd2ps { dst: *dst, src });
                    }
                }
            }
            DecodedOpcode::Cvtdq2pd => {
                if let [Operand::Xmm(dst), src] = instruction.operands.as_slice() {
                    let src = match src {
                        Operand::Xmm(src) => Some(VectorOperand::Register(*src)),
                        Operand::Memory(address) => Some(VectorOperand::Memory(*address)),
                        _ => None,
                    };
                    if let Some(src) = src {
                        ir.push(IrInstruction::Cvtdq2pd { dst: *dst, src });
                    }
                }
            }
            DecodedOpcode::Addsd => {
                if let [Operand::Xmm(dst), src] = instruction.operands.as_slice() {
                    let src = match src {
                        Operand::Xmm(src) => Some(VectorOperand::Register(*src)),
                        Operand::Memory(address) => Some(VectorOperand::Memory(*address)),
                        _ => None,
                    };
                    if let Some(src) = src {
                        ir.push(IrInstruction::Addsd { dst: *dst, src });
                    }
                }
            }
            DecodedOpcode::Divss => {
                if let [Operand::Xmm(dst), src] = instruction.operands.as_slice() {
                    let src = match src {
                        Operand::Xmm(src) => Some(VectorOperand::Register(*src)),
                        Operand::Memory(address) => Some(VectorOperand::Memory(*address)),
                        _ => None,
                    };
                    if let Some(src) = src {
                        ir.push(IrInstruction::Divss { dst: *dst, src });
                    }
                }
            }
            DecodedOpcode::Comiss => {
                if let [Operand::Xmm(lhs), rhs] = instruction.operands.as_slice() {
                    let rhs = match rhs {
                        Operand::Xmm(rhs) => Some(VectorOperand::Register(*rhs)),
                        Operand::Memory(address) => Some(VectorOperand::Memory(*address)),
                        _ => None,
                    };
                    if let Some(rhs) = rhs {
                        ir.push(IrInstruction::Comiss { lhs: *lhs, rhs });
                    }
                }
            }
            DecodedOpcode::SseArith { op, kind } => {
                if let [Operand::Xmm(dst), src] = instruction.operands.as_slice() {
                    let src = match src {
                        Operand::Xmm(src) => Some(VectorOperand::Register(*src)),
                        Operand::Memory(address) => Some(VectorOperand::Memory(*address)),
                        _ => None,
                    };
                    if let Some(src) = src {
                        ir.push(IrInstruction::SseArith {
                            op,
                            kind,
                            dst: *dst,
                            src,
                        });
                    }
                }
            }
            DecodedOpcode::SseSqrt { kind } => {
                if let [Operand::Xmm(dst), src] = instruction.operands.as_slice() {
                    let src = match src {
                        Operand::Xmm(src) => Some(VectorOperand::Register(*src)),
                        Operand::Memory(address) => Some(VectorOperand::Memory(*address)),
                        _ => None,
                    };
                    if let Some(src) = src {
                        ir.push(IrInstruction::SseSqrt {
                            kind,
                            dst: *dst,
                            src,
                        });
                    }
                }
            }
            DecodedOpcode::SseRcp => {
                if let [Operand::Xmm(dst), src] = instruction.operands.as_slice() {
                    let src = match src {
                        Operand::Xmm(src) => Some(VectorOperand::Register(*src)),
                        Operand::Memory(address) => Some(VectorOperand::Memory(*address)),
                        _ => None,
                    };
                    if let Some(src) = src {
                        ir.push(IrInstruction::SseRcp {
                            scalar: instruction.prefixes.contains(&InstructionPrefix::Rep),
                            dst: *dst,
                            src,
                        });
                    }
                }
            }
            DecodedOpcode::SseRsqrt => {
                if let [Operand::Xmm(dst), src] = instruction.operands.as_slice() {
                    let src = match src {
                        Operand::Xmm(src) => Some(VectorOperand::Register(*src)),
                        Operand::Memory(address) => Some(VectorOperand::Memory(*address)),
                        _ => None,
                    };
                    if let Some(src) = src {
                        ir.push(IrInstruction::SseRsqrt {
                            scalar: instruction.prefixes.contains(&InstructionPrefix::Rep),
                            dst: *dst,
                            src,
                        });
                    }
                }
            }
            DecodedOpcode::CvtIntToFloat => {
                if let [Operand::Xmm(dst), src] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::CvtIntToFloat {
                        to_double: instruction.prefixes.contains(&InstructionPrefix::Repne),
                        dst: *dst,
                        src: compare_operand(src.clone()),
                    });
                }
            }
            DecodedOpcode::CvtFloatToInt => {
                if let [Operand::Register(dst), src] = instruction.operands.as_slice() {
                    let src = match src {
                        Operand::Xmm(src) => Some(VectorOperand::Register(*src)),
                        Operand::Memory(address) => Some(VectorOperand::Memory(*address)),
                        _ => None,
                    };
                    if let Some(src) = src {
                        ir.push(IrInstruction::CvtFloatToInt {
                            truncate: !instruction.prefixes.contains(&InstructionPrefix::Rep),
                            is_double: instruction.prefixes.contains(&InstructionPrefix::Repne),
                            dst: *dst,
                            src,
                        });
                    }
                }
            }
            DecodedOpcode::Ucomi => {
                if let [Operand::Xmm(lhs), rhs] = instruction.operands.as_slice() {
                    let rhs = match rhs {
                        Operand::Xmm(rhs) => Some(VectorOperand::Register(*rhs)),
                        Operand::Memory(address) => Some(VectorOperand::Memory(*address)),
                        _ => None,
                    };
                    if let Some(rhs) = rhs {
                        ir.push(IrInstruction::Ucomi {
                            is_double: instruction
                                .prefixes
                                .contains(&InstructionPrefix::OperandSize),
                            lhs: *lhs,
                            rhs,
                        });
                    }
                }
            }
            DecodedOpcode::Pcmpistri => {
                if let [Operand::Xmm(lhs), rhs, Operand::ImmediateU64(imm)] =
                    instruction.operands.as_slice()
                {
                    let rhs = match rhs {
                        Operand::Xmm(rhs) => Some(VectorOperand::Register(*rhs)),
                        Operand::Memory(address) => Some(VectorOperand::Memory(*address)),
                        _ => None,
                    };
                    if let Some(rhs) = rhs {
                        ir.push(IrInstruction::Pcmpistri {
                            lhs: *lhs,
                            rhs,
                            imm: *imm as u8,
                        });
                    }
                }
            }
            DecodedOpcode::Fstcw => {
                if let [Operand::Memory(address)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::X87StoreControlWord { address: *address });
                }
            }
            DecodedOpcode::FstReal32 => {
                if let [Operand::Memory(address)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::X87Store {
                        address: *address,
                        width: 4,
                        pop: false,
                    });
                }
            }
            DecodedOpcode::FstReal64 => {
                if let [Operand::Memory(address)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::X87Store {
                        address: *address,
                        width: 8,
                        pop: false,
                    });
                }
            }
            DecodedOpcode::FstpReal32 => {
                if let [Operand::Memory(address)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::X87Store {
                        address: *address,
                        width: 4,
                        pop: true,
                    });
                }
            }
            DecodedOpcode::FstpSt => {
                if let [Operand::ImmediateU64(index)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::X87StorePopRegister {
                        index: *index as usize,
                    });
                }
            }
            DecodedOpcode::FstpReal => {
                if let [Operand::Memory(address)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::X87StorePop { address: *address });
                }
            }
            DecodedOpcode::Fcomi => {
                if let [Operand::ImmediateU64(index)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::X87Compare {
                        index: *index as usize,
                        pop: false,
                    });
                }
            }
            DecodedOpcode::Fcomip => {
                if let [Operand::ImmediateU64(index)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::X87Compare {
                        index: *index as usize,
                        pop: true,
                    });
                }
            }
            DecodedOpcode::Faddp => {
                if let [Operand::ImmediateU64(index)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::X87AddPop {
                        index: *index as usize,
                    });
                }
            }
            DecodedOpcode::FmulReal64 => {
                if let [Operand::Memory(address)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::X87MulMemory {
                        address: *address,
                        width: 8,
                    });
                }
            }
            DecodedOpcode::Fmul => {
                if let [Operand::ImmediateU64(index)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::X87Mul {
                        index: *index as usize,
                    });
                }
            }
            DecodedOpcode::Fdiv => {
                if let [Operand::ImmediateU64(index)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::X87DivRegister {
                        index: *index as usize,
                    });
                }
            }
            DecodedOpcode::Fdivp => {
                if let [Operand::ImmediateU64(index)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::X87DivPop {
                        index: *index as usize,
                    });
                }
            }
            DecodedOpcode::Fninit => ir.push(IrInstruction::X87Init),
            DecodedOpcode::LockCmpxchg => match instruction.operands.as_slice() {
                [
                    Operand::Memory(address),
                    Operand::Register(src),
                    Operand::ImmediateU64(width),
                ] => {
                    ir.push(IrInstruction::LockCmpxchg {
                        address: *address,
                        src: *src,
                        width: *width as usize,
                    });
                }
                [
                    Operand::Register(dst),
                    Operand::Register(src),
                    Operand::ImmediateU64(width),
                ] => {
                    ir.push(IrInstruction::CmpxchgRegisters {
                        dst: *dst,
                        src: *src,
                        width: *width as usize,
                    });
                }
                _ => {}
            },
            DecodedOpcode::LockCmpxchg8b => {
                if let [Operand::Memory(address)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::LockCmpxchg8b { address: *address });
                }
            }
            DecodedOpcode::LockXadd => match instruction.operands.as_slice() {
                [
                    Operand::Memory(address),
                    Operand::Register(src),
                    Operand::ImmediateU64(width),
                ] => {
                    ir.push(IrInstruction::LockXadd {
                        address: *address,
                        src: *src,
                        width: *width as usize,
                    });
                }
                [
                    Operand::Register(dst),
                    Operand::Register(src),
                    Operand::ImmediateU64(width),
                ] => {
                    ir.push(IrInstruction::XaddRegisters {
                        dst: *dst,
                        src: *src,
                        width: *width as usize,
                    });
                }
                _ => {}
            },
            // --- Phase 4.4 CPU Edge Cases: RDRAND, RDSEED, CLFLUSH, PREFETCH ---
            DecodedOpcode::Rdrand => {
                if let [Operand::Register(dst)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::Rdrand { dst: *dst });
                }
            }
            DecodedOpcode::Rdseed => {
                if let [Operand::Register(dst)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::Rdseed { dst: *dst });
                }
            }
            DecodedOpcode::Clflush => {
                // CLFLUSH/CLFLUSHOPT are no-ops on Apple Silicon; no IR instruction needed.
            }
            DecodedOpcode::Prefetch => {
                // PREFETCH hints are no-ops on Apple Silicon; emit nothing.
            }
            // --- BMI1/BMI2 instructions ---
            DecodedOpcode::Andn => {
                if let [
                    Operand::Register(dst),
                    Operand::Register(lhs),
                    Operand::Register(rhs),
                ] = instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::Andn {
                        dst: *dst,
                        lhs: *lhs,
                        rhs: *rhs,
                    });
                }
            }
            DecodedOpcode::Bextr => {
                if let [
                    Operand::Register(dst),
                    Operand::Register(src),
                    Operand::Register(range),
                ] = instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::Bextr {
                        dst: *dst,
                        src: *src,
                        range: *range,
                    });
                }
            }
            DecodedOpcode::Blsi => {
                if let [Operand::Register(dst), Operand::Register(src)] =
                    instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::Blsi {
                        dst: *dst,
                        src: *src,
                    });
                }
            }
            DecodedOpcode::Blsmsk => {
                if let [Operand::Register(dst), Operand::Register(src)] =
                    instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::Blsmsk {
                        dst: *dst,
                        src: *src,
                    });
                }
            }
            DecodedOpcode::Blsr => {
                if let [Operand::Register(dst), Operand::Register(src)] =
                    instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::Blsr {
                        dst: *dst,
                        src: *src,
                    });
                }
            }
            DecodedOpcode::Bzhi => {
                if let [
                    Operand::Register(dst),
                    Operand::Register(src),
                    Operand::Register(index),
                ] = instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::Bzhi {
                        dst: *dst,
                        src: *src,
                        index: *index,
                    });
                }
            }
            DecodedOpcode::Mulx => {
                if let [
                    Operand::Register(dst_lo),
                    Operand::Register(dst_hi),
                    Operand::Register(src),
                ] = instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::Mulx {
                        dst_lo: *dst_lo,
                        dst_hi: *dst_hi,
                        src: *src,
                    });
                }
            }
            DecodedOpcode::Pdep => {
                if let [
                    Operand::Register(dst),
                    Operand::Register(src),
                    Operand::Register(mask),
                ] = instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::Pdep {
                        dst: *dst,
                        src: *src,
                        mask: *mask,
                    });
                }
            }
            DecodedOpcode::Pext => {
                if let [
                    Operand::Register(dst),
                    Operand::Register(src),
                    Operand::Register(mask),
                ] = instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::Pext {
                        dst: *dst,
                        src: *src,
                        mask: *mask,
                    });
                }
            }
            DecodedOpcode::Rorx => {
                if let [
                    Operand::Register(dst),
                    Operand::Register(src),
                    Operand::ImmediateU64(imm),
                ] = instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::Rorx {
                        dst: *dst,
                        src: *src,
                        imm: *imm as u8,
                    });
                }
            }
            DecodedOpcode::Sarx => {
                if let [
                    Operand::Register(dst),
                    Operand::Register(src),
                    Operand::Register(shift),
                ] = instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::Sarx {
                        dst: *dst,
                        src: *src,
                        shift: *shift,
                    });
                }
            }
            DecodedOpcode::Shrx => {
                if let [
                    Operand::Register(dst),
                    Operand::Register(src),
                    Operand::Register(shift),
                ] = instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::Shrx {
                        dst: *dst,
                        src: *src,
                        shift: *shift,
                    });
                }
            }
            DecodedOpcode::Shlx => {
                if let [
                    Operand::Register(dst),
                    Operand::Register(src),
                    Operand::Register(shift),
                ] = instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::Shlx {
                        dst: *dst,
                        src: *src,
                        shift: *shift,
                    });
                }
            }
            // ADX instructions (ADCX, ADOX)
            DecodedOpcode::Adcx => {
                if let [Operand::Register(dst), src, Operand::ImmediateU64(width)] =
                    instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::Adcx {
                        dst: *dst,
                        src: compare_operand(src.clone()),
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::Adox => {
                if let [Operand::Register(dst), src, Operand::ImmediateU64(width)] =
                    instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::Adox {
                        dst: *dst,
                        src: compare_operand(src.clone()),
                        width: *width as usize,
                    });
                }
            }
            // FMA instructions
            DecodedOpcode::Vfmadd132ps
            | DecodedOpcode::Vfmadd132pd
            | DecodedOpcode::Vfmadd213ps
            | DecodedOpcode::Vfmadd213pd
            | DecodedOpcode::Vfmadd231ps
            | DecodedOpcode::Vfmadd231pd
            | DecodedOpcode::Vfmsub132ps
            | DecodedOpcode::Vfmsub132pd
            | DecodedOpcode::Vfmsub213ps
            | DecodedOpcode::Vfmsub213pd
            | DecodedOpcode::Vfmsub231ps
            | DecodedOpcode::Vfmsub231pd
            | DecodedOpcode::Vfnmadd132ps
            | DecodedOpcode::Vfnmadd132pd
            | DecodedOpcode::Vfnmadd213ps
            | DecodedOpcode::Vfnmadd213pd
            | DecodedOpcode::Vfnmadd231ps
            | DecodedOpcode::Vfnmadd231pd => {
                if let [
                    Operand::Xmm(dst),
                    Operand::Xmm(src1),
                    src2,
                    Operand::ImmediateU64(width),
                    Operand::ImmediateU64(element_kind),
                ] = instruction.operands.as_slice()
                {
                    let src2 = match src2 {
                        Operand::Xmm(reg) => VectorOperand::Register(*reg),
                        Operand::Memory(address) => VectorOperand::Memory(*address),
                        _ => continue,
                    };
                    let kind = match instruction.opcode {
                        DecodedOpcode::Vfmadd132ps | DecodedOpcode::Vfmadd132pd => {
                            FmaKind::Vfmadd132
                        }
                        DecodedOpcode::Vfmadd213ps | DecodedOpcode::Vfmadd213pd => {
                            FmaKind::Vfmadd213
                        }
                        DecodedOpcode::Vfmadd231ps | DecodedOpcode::Vfmadd231pd => {
                            FmaKind::Vfmadd231
                        }
                        DecodedOpcode::Vfmsub132ps | DecodedOpcode::Vfmsub132pd => {
                            FmaKind::Vfmsub132
                        }
                        DecodedOpcode::Vfmsub213ps | DecodedOpcode::Vfmsub213pd => {
                            FmaKind::Vfmsub213
                        }
                        DecodedOpcode::Vfmsub231ps | DecodedOpcode::Vfmsub231pd => {
                            FmaKind::Vfmsub231
                        }
                        DecodedOpcode::Vfnmadd132ps | DecodedOpcode::Vfnmadd132pd => {
                            FmaKind::Vfnmadd132
                        }
                        DecodedOpcode::Vfnmadd213ps | DecodedOpcode::Vfnmadd213pd => {
                            FmaKind::Vfnmadd213
                        }
                        DecodedOpcode::Vfnmadd231ps | DecodedOpcode::Vfnmadd231pd => {
                            FmaKind::Vfnmadd231
                        }
                        _ => continue,
                    };
                    ir.push(IrInstruction::FmaVector {
                        kind,
                        dst: *dst,
                        src1: *src1,
                        src2,
                        element_kind: *element_kind as u8,
                        width: *width as usize,
                    });
                }
            }
            // AVX-512 map=1 (0F38) permute instructions
            DecodedOpcode::Vpermps | DecodedOpcode::Vpermd => {
                if let [
                    Operand::Xmm(dst),
                    Operand::Xmm(indices),
                    src2,
                    Operand::ImmediateU64(width),
                    Operand::ImmediateU64(element_size),
                ] = instruction.operands.as_slice()
                {
                    let src2 = match src2 {
                        Operand::Xmm(reg) => VectorOperand::Register(*reg),
                        Operand::Memory(address) => VectorOperand::Memory(*address),
                        _ => continue,
                    };
                    if matches!(instruction.opcode, DecodedOpcode::Vpermps) {
                        ir.push(IrInstruction::PermuteVarPsPd {
                            dst: *dst,
                            src: src2,
                            indices: *indices,
                            element_size: *element_size as u8,
                            width: *width as usize,
                            evex: instruction.evex_info,
                        });
                    } else {
                        ir.push(IrInstruction::PermuteVarDq {
                            dst: *dst,
                            src: *indices,
                            indices: src2,
                            element_size: *element_size as u8,
                            width: *width as usize,
                            evex: instruction.evex_info,
                        });
                    }
                }
            }
            DecodedOpcode::Vpermpd | DecodedOpcode::Vpermq => {
                if let [
                    Operand::Xmm(dst),
                    Operand::Xmm(indices),
                    src2,
                    Operand::ImmediateU64(width),
                    Operand::ImmediateU64(element_size),
                ] = instruction.operands.as_slice()
                {
                    let src2 = match src2 {
                        Operand::Xmm(reg) => VectorOperand::Register(*reg),
                        Operand::Memory(address) => VectorOperand::Memory(*address),
                        _ => continue,
                    };
                    if matches!(instruction.opcode, DecodedOpcode::Vpermpd) {
                        ir.push(IrInstruction::PermuteVarPsPd {
                            dst: *dst,
                            src: src2,
                            indices: *indices,
                            element_size: *element_size as u8,
                            width: *width as usize,
                            evex: instruction.evex_info,
                        });
                    } else {
                        ir.push(IrInstruction::PermuteVarDq {
                            dst: *dst,
                            src: *indices,
                            indices: src2,
                            element_size: *element_size as u8,
                            width: *width as usize,
                            evex: instruction.evex_info,
                        });
                    }
                }
            }
            DecodedOpcode::Vpermi2d
            | DecodedOpcode::Vpermi2q
            | DecodedOpcode::Vpermi2ps
            | DecodedOpcode::Vpermi2pd => {
                if let [
                    Operand::Xmm(dst),
                    Operand::Xmm(idx),
                    src2,
                    Operand::ImmediateU64(width),
                    Operand::ImmediateU64(element_size),
                ] = instruction.operands.as_slice()
                {
                    let src2 = match src2 {
                        Operand::Xmm(reg) => VectorOperand::Register(*reg),
                        Operand::Memory(address) => VectorOperand::Memory(*address),
                        _ => continue,
                    };
                    ir.push(IrInstruction::PermuteI2 {
                        dst: *dst,
                        src1: *dst,
                        src2,
                        indices: *idx,
                        element_size: *element_size as u8,
                        width: *width as usize,
                        evex: instruction.evex_info,
                    });
                }
            }
            DecodedOpcode::Vpermt2d
            | DecodedOpcode::Vpermt2q
            | DecodedOpcode::Vpermt2ps
            | DecodedOpcode::Vpermt2pd => {
                if let [
                    Operand::Xmm(dst),
                    Operand::Xmm(idx),
                    src2,
                    Operand::ImmediateU64(width),
                    Operand::ImmediateU64(element_size),
                ] = instruction.operands.as_slice()
                {
                    let src2 = match src2 {
                        Operand::Xmm(reg) => VectorOperand::Register(*reg),
                        Operand::Memory(address) => VectorOperand::Memory(*address),
                        _ => continue,
                    };
                    ir.push(IrInstruction::PermuteT2 {
                        dst: *dst,
                        src1: *dst,
                        src2,
                        indices: *idx,
                        element_size: *element_size as u8,
                        width: *width as usize,
                        evex: instruction.evex_info,
                    });
                }
            }
            DecodedOpcode::Vfixupimmps | DecodedOpcode::Vfixupimmpd => {
                if let [
                    Operand::Xmm(dst),
                    Operand::Xmm(src1),
                    src2,
                    Operand::ImmediateU64(width),
                    Operand::ImmediateU64(element_size),
                ] = instruction.operands.as_slice()
                {
                    let src2 = match src2 {
                        Operand::Xmm(reg) => VectorOperand::Register(*reg),
                        Operand::Memory(address) => VectorOperand::Memory(*address),
                        _ => continue,
                    };
                    ir.push(IrInstruction::FixupSpecial {
                        dst: *dst,
                        src1: *src1,
                        src2,
                        table: 0,
                        element_size: *element_size as u8,
                        width: *width as usize,
                        evex: instruction.evex_info,
                    });
                }
            }
            DecodedOpcode::Vgetexpps | DecodedOpcode::Vgetexppd => {
                if let [
                    Operand::Xmm(dst),
                    src,
                    Operand::ImmediateU64(width),
                    Operand::ImmediateU64(element_size),
                ] = instruction.operands.as_slice()
                {
                    let src = match src {
                        Operand::Xmm(reg) => VectorOperand::Register(*reg),
                        Operand::Memory(address) => VectorOperand::Memory(*address),
                        _ => continue,
                    };
                    ir.push(IrInstruction::ExtractExponent {
                        dst: *dst,
                        src,
                        element_size: *element_size as u8,
                        width: *width as usize,
                        evex: instruction.evex_info,
                    });
                }
            }
            DecodedOpcode::Vgetmantps | DecodedOpcode::Vgetmantpd => {
                if let [
                    Operand::Xmm(dst),
                    src,
                    Operand::ImmediateU64(width),
                    Operand::ImmediateU64(element_size),
                ] = instruction.operands.as_slice()
                {
                    let src = match src {
                        Operand::Xmm(reg) => VectorOperand::Register(*reg),
                        Operand::Memory(address) => VectorOperand::Memory(*address),
                        _ => continue,
                    };
                    ir.push(IrInstruction::ExtractMantissa {
                        dst: *dst,
                        src,
                        element_size: *element_size as u8,
                        norm: 0,
                        sign: 0,
                        width: *width as usize,
                        evex: instruction.evex_info,
                    });
                }
            }
            DecodedOpcode::Vreduceps | DecodedOpcode::Vreducepd => {
                if let [
                    Operand::Xmm(dst),
                    src,
                    Operand::ImmediateU64(width),
                    Operand::ImmediateU64(element_size),
                ] = instruction.operands.as_slice()
                {
                    let src = match src {
                        Operand::Xmm(reg) => VectorOperand::Register(*reg),
                        Operand::Memory(address) => VectorOperand::Memory(*address),
                        _ => continue,
                    };
                    ir.push(IrInstruction::ReducePrecision {
                        dst: *dst,
                        src,
                        element_size: *element_size as u8,
                        reduce_op: 0,
                        width: *width as usize,
                        evex: instruction.evex_info,
                    });
                }
            }
            DecodedOpcode::Vrangeps | DecodedOpcode::Vrangepd => {
                if let [
                    Operand::Xmm(dst),
                    Operand::Xmm(src1),
                    src2,
                    Operand::ImmediateU64(width),
                    Operand::ImmediateU64(element_size),
                ] = instruction.operands.as_slice()
                {
                    let src2 = match src2 {
                        Operand::Xmm(reg) => VectorOperand::Register(*reg),
                        Operand::Memory(address) => VectorOperand::Memory(*address),
                        _ => continue,
                    };
                    ir.push(IrInstruction::RangePacked {
                        dst: *dst,
                        src1: *src1,
                        src2,
                        element_size: *element_size as u8,
                        predicate: 0,
                        width: *width as usize,
                        evex: instruction.evex_info,
                    });
                }
            }
            DecodedOpcode::Vscalefps | DecodedOpcode::Vscalefpd => {
                if let [
                    Operand::Xmm(dst),
                    Operand::Xmm(src1),
                    src2,
                    Operand::ImmediateU64(width),
                    Operand::ImmediateU64(element_size),
                ] = instruction.operands.as_slice()
                {
                    let src2 = match src2 {
                        Operand::Xmm(reg) => VectorOperand::Register(*reg),
                        Operand::Memory(address) => VectorOperand::Memory(*address),
                        _ => continue,
                    };
                    ir.push(IrInstruction::ScaleByPower2 {
                        dst: *dst,
                        src1: *src1,
                        src2,
                        element_size: *element_size as u8,
                        width: *width as usize,
                        evex: instruction.evex_info,
                    });
                }
            }
            DecodedOpcode::Vfpclassps | DecodedOpcode::Vfpclasspd => {
                if let [
                    Operand::Xmm(dst),
                    src,
                    Operand::ImmediateU64(width),
                    Operand::ImmediateU64(element_size),
                ] = instruction.operands.as_slice()
                {
                    let src = match src {
                        Operand::Xmm(reg) => VectorOperand::Register(*reg),
                        Operand::Memory(address) => VectorOperand::Memory(*address),
                        _ => continue,
                    };
                    ir.push(IrInstruction::FloatClass {
                        dst_mask: *dst,
                        src,
                        element_size: *element_size as u8,
                        class_mask: 0,
                        width: *width as usize,
                        evex: instruction.evex_info,
                    });
                }
            }
            DecodedOpcode::Vpternlogd | DecodedOpcode::Vpternlogq => {
                if let [
                    Operand::Xmm(dst),
                    Operand::Xmm(src1),
                    src2,
                    Operand::ImmediateU64(width),
                    Operand::ImmediateU64(element_size),
                ] = instruction.operands.as_slice()
                {
                    let src2 = match src2 {
                        Operand::Xmm(reg) => VectorOperand::Register(*reg),
                        Operand::Memory(address) => VectorOperand::Memory(*address),
                        _ => continue,
                    };
                    ir.push(IrInstruction::Pternlog {
                        dst: *dst,
                        src1: *src1,
                        src2,
                        truth_table: 0,
                        element_size: *element_size as u8,
                        width: *width as usize,
                        evex: instruction.evex_info,
                    });
                }
            }
            DecodedOpcode::Vpconflictd | DecodedOpcode::Vpconflictq => {
                if let [
                    Operand::Xmm(dst),
                    src,
                    Operand::ImmediateU64(width),
                    Operand::ImmediateU64(element_size),
                ] = instruction.operands.as_slice()
                {
                    let src = match src {
                        Operand::Xmm(reg) => VectorOperand::Register(*reg),
                        Operand::Memory(address) => VectorOperand::Memory(*address),
                        _ => continue,
                    };
                    ir.push(IrInstruction::ConflictDetect {
                        dst: *dst,
                        src,
                        element_size: *element_size as u8,
                        width: *width as usize,
                        evex: instruction.evex_info,
                    });
                }
            }
            DecodedOpcode::Vcompressps | DecodedOpcode::Vcompresspd => {
                if let [
                    dst_op,
                    Operand::Xmm(src),
                    Operand::ImmediateU64(width),
                    Operand::ImmediateU64(element_size),
                ] = instruction.operands.as_slice()
                {
                    let dst = match dst_op {
                        Operand::Xmm(reg) => VectorOperand::Register(*reg),
                        Operand::Memory(address) => VectorOperand::Memory(*address),
                        _ => continue,
                    };
                    ir.push(IrInstruction::CompressVector {
                        dst,
                        src: *src,
                        element_size: *element_size as u8,
                        width: *width as usize,
                        evex: instruction.evex_info,
                    });
                }
            }
            DecodedOpcode::Vexpandps | DecodedOpcode::Vexpandpd => {
                if let [
                    Operand::Xmm(dst),
                    src,
                    Operand::ImmediateU64(width),
                    Operand::ImmediateU64(element_size),
                ] = instruction.operands.as_slice()
                {
                    let src = match src {
                        Operand::Xmm(reg) => VectorOperand::Register(*reg),
                        Operand::Memory(address) => VectorOperand::Memory(*address),
                        _ => continue,
                    };
                    ir.push(IrInstruction::ExpandVector {
                        dst: *dst,
                        src,
                        element_size: *element_size as u8,
                        width: *width as usize,
                        evex: instruction.evex_info,
                    });
                }
            }
            DecodedOpcode::Vgatherdps
            | DecodedOpcode::Vgatherdpd
            | DecodedOpcode::Vgatherqps
            | DecodedOpcode::Vgatherqpd => {
                if let [
                    Operand::Xmm(dst),
                    Operand::Xmm(vsib),
                    Operand::ImmediateU64(width),
                    Operand::ImmediateU64(element_size),
                ] = instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::GatherVector {
                        dst: *dst,
                        base_addr: VectorOperand::Register(*vsib),
                        indices: *vsib,
                        scale: *element_size as u8,
                        element_size: *element_size as u8,
                        width: *width as usize,
                        evex: instruction.evex_info,
                    });
                }
            }
            DecodedOpcode::Vscatterdps
            | DecodedOpcode::Vscatterdpd
            | DecodedOpcode::Vscatterqps
            | DecodedOpcode::Vscatterqpd => {
                if let [
                    Operand::Xmm(vsib),
                    Operand::Xmm(src),
                    Operand::ImmediateU64(width),
                    Operand::ImmediateU64(element_size),
                ] = instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::ScatterVector {
                        base_addr: VectorOperand::Register(*vsib),
                        indices: *vsib,
                        src: *src,
                        scale: *element_size as u8,
                        element_size: *element_size as u8,
                        width: *width as usize,
                        evex: instruction.evex_info,
                    });
                }
            }
            // AVX-512 map=0 arithmetic
            DecodedOpcode::Vaddps
            | DecodedOpcode::Vaddpd
            | DecodedOpcode::Vmulps
            | DecodedOpcode::Vmulpd
            | DecodedOpcode::Vsubps
            | DecodedOpcode::Vsubpd
            | DecodedOpcode::Vdivps
            | DecodedOpcode::Vdivpd
            | DecodedOpcode::Vminps
            | DecodedOpcode::Vminpd
            | DecodedOpcode::Vmaxps
            | DecodedOpcode::Vmaxpd => {
                if let [
                    Operand::Xmm(dst),
                    Operand::Xmm(src1),
                    src2,
                    Operand::ImmediateU64(width),
                    Operand::ImmediateU64(element_size),
                ] = instruction.operands.as_slice()
                {
                    let src2 = match src2 {
                        Operand::Xmm(reg) => VectorOperand::Register(*reg),
                        Operand::Memory(address) => VectorOperand::Memory(*address),
                        _ => continue,
                    };
                    let op = match instruction.opcode {
                        DecodedOpcode::Vaddps | DecodedOpcode::Vaddpd => IrInstruction::AddPacked {
                            dst: *dst,
                            src1: *src1,
                            src2,
                            element_size: *element_size as u8,
                            width: *width as usize,
                            evex: instruction.evex_info,
                        },
                        DecodedOpcode::Vmulps | DecodedOpcode::Vmulpd => IrInstruction::MulPacked {
                            dst: *dst,
                            src1: *src1,
                            src2,
                            element_size: *element_size as u8,
                            width: *width as usize,
                            evex: instruction.evex_info,
                        },
                        DecodedOpcode::Vsubps | DecodedOpcode::Vsubpd => IrInstruction::SubPacked {
                            dst: *dst,
                            src1: *src1,
                            src2,
                            element_size: *element_size as u8,
                            width: *width as usize,
                            evex: instruction.evex_info,
                        },
                        DecodedOpcode::Vdivps | DecodedOpcode::Vdivpd => IrInstruction::DivPacked {
                            dst: *dst,
                            src1: *src1,
                            src2,
                            element_size: *element_size as u8,
                            width: *width as usize,
                            evex: instruction.evex_info,
                        },
                        DecodedOpcode::Vminps | DecodedOpcode::Vminpd => IrInstruction::MinPacked {
                            dst: *dst,
                            src1: *src1,
                            src2,
                            element_size: *element_size as u8,
                            width: *width as usize,
                            evex: instruction.evex_info,
                        },
                        DecodedOpcode::Vmaxps | DecodedOpcode::Vmaxpd => IrInstruction::MaxPacked {
                            dst: *dst,
                            src1: *src1,
                            src2,
                            element_size: *element_size as u8,
                            width: *width as usize,
                            evex: instruction.evex_info,
                        },
                        _ => continue,
                    };
                    ir.push(op);
                }
            }
            DecodedOpcode::Vsqrtps | DecodedOpcode::Vsqrtpd => {
                if let [
                    Operand::Xmm(dst),
                    src,
                    Operand::ImmediateU64(width),
                    Operand::ImmediateU64(element_size),
                ] = instruction.operands.as_slice()
                {
                    let src = match src {
                        Operand::Xmm(reg) => VectorOperand::Register(*reg),
                        Operand::Memory(address) => VectorOperand::Memory(*address),
                        _ => continue,
                    };
                    ir.push(IrInstruction::SqrtPacked {
                        dst: *dst,
                        src,
                        element_size: *element_size as u8,
                        width: *width as usize,
                        evex: instruction.evex_info,
                    });
                }
            }
            DecodedOpcode::Vcmpps | DecodedOpcode::Vcmppd => {
                if let [
                    Operand::Xmm(dst),
                    Operand::Xmm(src1),
                    src2,
                    Operand::ImmediateU64(width),
                    Operand::ImmediateU64(element_size),
                    Operand::ImmediateU64(predicate),
                ] = instruction.operands.as_slice()
                {
                    let src2 = match src2 {
                        Operand::Xmm(reg) => VectorOperand::Register(*reg),
                        Operand::Memory(address) => VectorOperand::Memory(*address),
                        _ => continue,
                    };
                    ir.push(IrInstruction::ComparePacked {
                        dst_mask: *dst,
                        src1: *src1,
                        src2,
                        element_size: *element_size as u8,
                        predicate: *predicate as u8,
                        width: *width as usize,
                        evex: instruction.evex_info,
                    });
                }
            }
            DecodedOpcode::Vcvtps2pd
            | DecodedOpcode::Vcvtpd2ps
            | DecodedOpcode::Vcvtps2dq
            | DecodedOpcode::Vcvtdq2ps => {
                if let [
                    Operand::Xmm(dst),
                    src,
                    Operand::ImmediateU64(width),
                    Operand::ImmediateU64(_element_size),
                ] = instruction.operands.as_slice()
                {
                    let src = match src {
                        Operand::Xmm(reg) => VectorOperand::Register(*reg),
                        Operand::Memory(address) => VectorOperand::Memory(*address),
                        _ => continue,
                    };
                    let (from_size, to_size) = match instruction.opcode {
                        DecodedOpcode::Vcvtps2pd => (4u8, 8u8),
                        DecodedOpcode::Vcvtpd2ps => (8u8, 4u8),
                        DecodedOpcode::Vcvtps2dq => (4u8, 4u8),
                        DecodedOpcode::Vcvtdq2ps => (4u8, 4u8),
                        _ => continue,
                    };
                    ir.push(IrInstruction::ConvertPacked {
                        dst: *dst,
                        src,
                        from_size,
                        to_size,
                        width: *width as usize,
                        evex: instruction.evex_info,
                    });
                }
            }
            DecodedOpcode::Vcvtusi2ss => {
                if let [Operand::Xmm(dst), src, Operand::ImmediateU64(width)] =
                    instruction.operands.as_slice()
                {
                    let src = match src {
                        Operand::Register(reg) => VectorOperand::Register(reg.index() as u8),
                        Operand::Memory(address) => VectorOperand::Memory(*address),
                        _ => continue,
                    };
                    ir.push(IrInstruction::ConvertFromInt {
                        dst: *dst,
                        src,
                        from_int_size: *width as u8,
                        to_size: 4,
                        unsigned: true,
                        width: *width as usize,
                        evex: instruction.evex_info,
                    });
                }
            }
            DecodedOpcode::Vcvtss2si => {
                if let [Operand::Register(dst), src] = instruction.operands.as_slice() {
                    let src = match src {
                        Operand::Xmm(reg) => VectorOperand::Register(*reg),
                        Operand::Memory(address) => VectorOperand::Memory(*address),
                        _ => continue,
                    };
                    ir.push(IrInstruction::ConvertToInt {
                        dst: dst.index() as u8,
                        src,
                        from_size: 4,
                        to_int_size: 4,
                        truncate: false,
                        width: 4,
                        evex: instruction.evex_info,
                    });
                }
            }
            DecodedOpcode::Vcvttss2si => {
                if let [Operand::Register(dst), src] = instruction.operands.as_slice() {
                    let src = match src {
                        Operand::Xmm(reg) => VectorOperand::Register(*reg),
                        Operand::Memory(address) => VectorOperand::Memory(*address),
                        _ => continue,
                    };
                    ir.push(IrInstruction::ConvertToInt {
                        dst: dst.index() as u8,
                        src,
                        from_size: 4,
                        to_int_size: 4,
                        truncate: true,
                        width: 4,
                        evex: instruction.evex_info,
                    });
                }
            }
            // AVX-512 map=2 insert/extract/broadcast
            DecodedOpcode::Vinsertf128
            | DecodedOpcode::Vinserti128
            | DecodedOpcode::Vinsertf256
            | DecodedOpcode::Vinserti256
            | DecodedOpcode::Vinsertf32x4
            | DecodedOpcode::Vinserti32x4
            | DecodedOpcode::Vinsertf64x2
            | DecodedOpcode::Vinserti64x2
            | DecodedOpcode::Vinsertf64x4
            | DecodedOpcode::Vinserti64x4
            | DecodedOpcode::Vinsertf32x8
            | DecodedOpcode::Vinserti32x8 => {
                if let [
                    Operand::Xmm(dst),
                    Operand::Xmm(src1),
                    src2,
                    Operand::ImmediateU64(imm),
                    Operand::ImmediateU64(width),
                    Operand::ImmediateU64(element_size),
                ] = instruction.operands.as_slice()
                {
                    let sub_src = match src2 {
                        Operand::Xmm(reg) => VectorOperand::Register(*reg),
                        Operand::Memory(address) => VectorOperand::Memory(*address),
                        _ => continue,
                    };
                    ir.push(IrInstruction::InsertSubVector {
                        dst: *dst,
                        src: *src1,
                        sub_src,
                        index: *imm as u8,
                        element_size: *element_size as u8,
                        width: *width as usize,
                        evex: instruction.evex_info,
                    });
                }
            }
            DecodedOpcode::Vextractf128
            | DecodedOpcode::Vextracti128
            | DecodedOpcode::Vextractf256
            | DecodedOpcode::Vextracti256
            | DecodedOpcode::Vextractf32x4
            | DecodedOpcode::Vextracti32x4
            | DecodedOpcode::Vextractf64x2
            | DecodedOpcode::Vextracti64x2
            | DecodedOpcode::Vextractf64x4
            | DecodedOpcode::Vextracti64x4
            | DecodedOpcode::Vextractf32x8
            | DecodedOpcode::Vextracti32x8 => {
                if let [
                    dst_op,
                    Operand::Xmm(src),
                    Operand::ImmediateU64(imm),
                    Operand::ImmediateU64(width),
                    Operand::ImmediateU64(element_size),
                ] = instruction.operands.as_slice()
                {
                    let dst = match dst_op {
                        Operand::Xmm(reg) => VectorOperand::Register(*reg),
                        Operand::Memory(address) => VectorOperand::Memory(*address),
                        _ => continue,
                    };
                    ir.push(IrInstruction::ExtractSubVector {
                        dst,
                        src: VectorOperand::Register(*src),
                        index: *imm as u8,
                        element_size: *element_size as u8,
                        width: *width as usize,
                        evex: instruction.evex_info,
                    });
                }
            }
            DecodedOpcode::Vbroadcastf32x4
            | DecodedOpcode::Vbroadcasti32x4
            | DecodedOpcode::Vbroadcastf64x2
            | DecodedOpcode::Vbroadcasti64x2
            | DecodedOpcode::Vbroadcastf32x8
            | DecodedOpcode::Vbroadcasti32x8
            | DecodedOpcode::Vbroadcastf64x4
            | DecodedOpcode::Vbroadcasti64x4 => {
                if let [
                    Operand::Xmm(dst),
                    src,
                    Operand::ImmediateU64(width),
                    Operand::ImmediateU64(element_size),
                ] = instruction.operands.as_slice()
                {
                    let src = match src {
                        Operand::Xmm(reg) => VectorOperand::Register(*reg),
                        Operand::Memory(address) => VectorOperand::Memory(*address),
                        _ => continue,
                    };
                    ir.push(IrInstruction::BroadcastSubVector {
                        dst: *dst,
                        src,
                        element_size: *element_size as u8,
                        width: *width as usize,
                        evex: instruction.evex_info,
                    });
                }
            }
            DecodedOpcode::Vbroadcastm => {
                if let [
                    Operand::Xmm(dst),
                    Operand::ImmediateU64(src_k),
                    Operand::ImmediateU64(width),
                ] = instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::BroadcastMask {
                        dst: *dst,
                        src: *src_k as u8,
                        width: *width as usize,
                    });
                }
            }
            DecodedOpcode::ValignD | DecodedOpcode::ValignQ => {
                if let [
                    Operand::Xmm(dst),
                    Operand::Xmm(src1),
                    src2,
                    Operand::ImmediateU64(imm),
                    Operand::ImmediateU64(width),
                ] = instruction.operands.as_slice()
                {
                    let src2 = match src2 {
                        Operand::Xmm(reg) => VectorOperand::Register(*reg),
                        Operand::Memory(address) => VectorOperand::Memory(*address),
                        _ => continue,
                    };
                    if matches!(instruction.opcode, DecodedOpcode::ValignD) {
                        ir.push(IrInstruction::AlignD {
                            dst: *dst,
                            src1: *src1,
                            src2,
                            imm: *imm as u8,
                            width: *width as usize,
                            evex: instruction.evex_info,
                        });
                    } else {
                        ir.push(IrInstruction::AlignQ {
                            dst: *dst,
                            src1: *src1,
                            src2,
                            imm: *imm as u8,
                            width: *width as usize,
                            evex: instruction.evex_info,
                        });
                    }
                }
            }
            DecodedOpcode::Vpermil2ps | DecodedOpcode::Vpermil2pd => {
                if let [
                    Operand::Xmm(dst),
                    Operand::Xmm(src1),
                    src2,
                    Operand::ImmediateU64(imm),
                    Operand::ImmediateU64(width),
                ] = instruction.operands.as_slice()
                {
                    let src2 = match src2 {
                        Operand::Xmm(reg) => VectorOperand::Register(*reg),
                        Operand::Memory(address) => VectorOperand::Memory(*address),
                        _ => continue,
                    };
                    let es = if matches!(instruction.opcode, DecodedOpcode::Vpermil2ps) {
                        0
                    } else {
                        1
                    };
                    ir.push(IrInstruction::PermuteImm2Src {
                        dst: *dst,
                        src1: *src1,
                        src2,
                        imm: *imm as u8,
                        element_size: es,
                        width: *width as usize,
                        evex: instruction.evex_info,
                    });
                }
            }
            DecodedOpcode::Vpermilps | DecodedOpcode::Vpermilpd => {
                if let [
                    Operand::Xmm(dst),
                    src,
                    Operand::ImmediateU64(imm),
                    Operand::ImmediateU64(width),
                ] = instruction.operands.as_slice()
                {
                    let src = match src {
                        Operand::Xmm(reg) => VectorOperand::Register(*reg),
                        Operand::Memory(address) => VectorOperand::Memory(*address),
                        _ => continue,
                    };
                    let es = if matches!(instruction.opcode, DecodedOpcode::Vpermilps) {
                        0
                    } else {
                        1
                    };
                    ir.push(IrInstruction::PermuteImm {
                        dst: *dst,
                        src,
                        imm: *imm as u8,
                        element_size: es,
                        width: *width as usize,
                        evex: instruction.evex_info,
                    });
                }
            }
            // Mask register operations — derive size from opcode suffix (B=8, W=16, D=32, Q=64)
            DecodedOpcode::KandB
            | DecodedOpcode::KandW
            | DecodedOpcode::KandD
            | DecodedOpcode::KandQ => {
                if let [Operand::Xmm(dst), Operand::Xmm(src1), Operand::Xmm(src2)] =
                    instruction.operands.as_slice()
                {
                    let size = mask_op_size(&instruction.opcode);
                    ir.push(IrInstruction::Kand {
                        dst: *dst,
                        src1: *src1,
                        src2: *src2,
                        size,
                    });
                }
            }
            DecodedOpcode::KorB
            | DecodedOpcode::KorW
            | DecodedOpcode::KorD
            | DecodedOpcode::KorQ => {
                if let [Operand::Xmm(dst), Operand::Xmm(src1), Operand::Xmm(src2)] =
                    instruction.operands.as_slice()
                {
                    let size = mask_op_size(&instruction.opcode);
                    ir.push(IrInstruction::Kor {
                        dst: *dst,
                        src1: *src1,
                        src2: *src2,
                        size,
                    });
                }
            }
            DecodedOpcode::KxorB
            | DecodedOpcode::KxorW
            | DecodedOpcode::KxorD
            | DecodedOpcode::KxorQ => {
                if let [Operand::Xmm(dst), Operand::Xmm(src1), Operand::Xmm(src2)] =
                    instruction.operands.as_slice()
                {
                    let size = mask_op_size(&instruction.opcode);
                    ir.push(IrInstruction::Kxor {
                        dst: *dst,
                        src1: *src1,
                        src2: *src2,
                        size,
                    });
                }
            }
            DecodedOpcode::KnotB
            | DecodedOpcode::KnotW
            | DecodedOpcode::KnotD
            | DecodedOpcode::KnotQ => {
                if let [Operand::Xmm(dst), Operand::Xmm(src)] = instruction.operands.as_slice() {
                    let size = mask_op_size(&instruction.opcode);
                    ir.push(IrInstruction::Knot {
                        dst: *dst,
                        src: *src,
                        size,
                    });
                }
            }
            DecodedOpcode::KshiftlB
            | DecodedOpcode::KshiftlW
            | DecodedOpcode::KshiftlD
            | DecodedOpcode::KshiftlQ => {
                if let [
                    Operand::Xmm(dst),
                    Operand::Xmm(src),
                    Operand::ImmediateU64(imm),
                ] = instruction.operands.as_slice()
                {
                    let size = mask_op_size(&instruction.opcode);
                    ir.push(IrInstruction::Kshiftl {
                        dst: *dst,
                        src: *src,
                        count: *imm as u8,
                        size,
                    });
                }
            }
            DecodedOpcode::KshiftrB
            | DecodedOpcode::KshiftrW
            | DecodedOpcode::KshiftrD
            | DecodedOpcode::KshiftrQ => {
                if let [
                    Operand::Xmm(dst),
                    Operand::Xmm(src),
                    Operand::ImmediateU64(imm),
                ] = instruction.operands.as_slice()
                {
                    let size = mask_op_size(&instruction.opcode);
                    ir.push(IrInstruction::Kshiftr {
                        dst: *dst,
                        src: *src,
                        count: *imm as u8,
                        size,
                    });
                }
            }
            DecodedOpcode::KaddB
            | DecodedOpcode::KaddW
            | DecodedOpcode::KaddD
            | DecodedOpcode::KaddQ => {
                if let [Operand::Xmm(dst), Operand::Xmm(src1), Operand::Xmm(src2)] =
                    instruction.operands.as_slice()
                {
                    let size = mask_op_size(&instruction.opcode);
                    ir.push(IrInstruction::Kadd {
                        dst: *dst,
                        src1: *src1,
                        src2: *src2,
                        size,
                    });
                }
            }
            DecodedOpcode::KtestB
            | DecodedOpcode::KtestW
            | DecodedOpcode::KtestD
            | DecodedOpcode::KtestQ => {
                if let [Operand::Xmm(src1), Operand::Xmm(src2)] = instruction.operands.as_slice() {
                    let size = mask_op_size(&instruction.opcode);
                    ir.push(IrInstruction::Ktest {
                        src1: *src1,
                        src2: *src2,
                        size,
                    });
                }
            }
            DecodedOpcode::Kunpckbw | DecodedOpcode::Kunpckwd | DecodedOpcode::Kunpckdq => {
                if let [
                    Operand::Xmm(dst),
                    Operand::Xmm(src1),
                    Operand::Xmm(src2),
                    Operand::ImmediateU64(_imm),
                ] = instruction.operands.as_slice()
                {
                    let size = mask_op_size(&instruction.opcode);
                    ir.push(IrInstruction::Kunpck {
                        dst: *dst,
                        src1: *src1,
                        src2: *src2,
                        size,
                    });
                }
            }
            // AES-NI instructions (software implementation)
            DecodedOpcode::Aesenc => {
                if let [Operand::Xmm(dst), Operand::Xmm(src)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::AesEnc {
                        dst: *dst,
                        src: *src,
                    });
                }
            }
            DecodedOpcode::Aesenclast => {
                if let [Operand::Xmm(dst), Operand::Xmm(src)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::AesEncLast {
                        dst: *dst,
                        src: *src,
                    });
                }
            }
            DecodedOpcode::Aesdec => {
                if let [Operand::Xmm(dst), Operand::Xmm(src)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::AesDec {
                        dst: *dst,
                        src: *src,
                    });
                }
            }
            DecodedOpcode::Aesdeclast => {
                if let [Operand::Xmm(dst), Operand::Xmm(src)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::AesDecLast {
                        dst: *dst,
                        src: *src,
                    });
                }
            }
            DecodedOpcode::Aesimc => {
                if let [Operand::Xmm(dst), Operand::Xmm(src)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::AesImc {
                        dst: *dst,
                        src: *src,
                    });
                }
            }
            DecodedOpcode::Aeskeygenassist => {
                if let [
                    Operand::Xmm(dst),
                    Operand::Xmm(src),
                    Operand::ImmediateU64(imm),
                ] = instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::AesKeyGenAssist {
                        dst: *dst,
                        src: *src,
                        imm: *imm as u8,
                    });
                }
            }
            // PCLMULQDQ (software implementation)
            DecodedOpcode::Pclmulqdq => {
                if let [
                    Operand::Xmm(dst),
                    Operand::Xmm(src),
                    Operand::ImmediateU64(imm),
                ] = instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::Pclmulqdq {
                        dst: *dst,
                        src: *src,
                        imm: *imm as u8,
                    });
                }
            }
            // SHA instructions (software implementation)
            DecodedOpcode::Sha1rnds4 => {
                if let [
                    Operand::Xmm(dst),
                    Operand::Xmm(src),
                    Operand::ImmediateU64(imm),
                ] = instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::Sha1Rnds4 {
                        dst: *dst,
                        src: *src,
                        imm: *imm as u8,
                    });
                }
            }
            DecodedOpcode::Sha1nexte => {
                if let [Operand::Xmm(dst), Operand::Xmm(src)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::Sha1NextE {
                        dst: *dst,
                        src: *src,
                    });
                }
            }
            DecodedOpcode::Sha1msg1 => {
                if let [Operand::Xmm(dst), Operand::Xmm(src)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::Sha1Msg1 {
                        dst: *dst,
                        src: *src,
                    });
                }
            }
            DecodedOpcode::Sha1msg2 => {
                if let [Operand::Xmm(dst), Operand::Xmm(src)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::Sha1Msg2 {
                        dst: *dst,
                        src: *src,
                    });
                }
            }
            DecodedOpcode::Sha256rnds2 => {
                if let [Operand::Xmm(dst), Operand::Xmm(src)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::Sha256Rnds2 {
                        dst: *dst,
                        src: *src,
                    });
                }
            }
            DecodedOpcode::Sha256msg1 => {
                if let [Operand::Xmm(dst), Operand::Xmm(src)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::Sha256Msg1 {
                        dst: *dst,
                        src: *src,
                    });
                }
            }
            DecodedOpcode::Sha256msg2 => {
                if let [Operand::Xmm(dst), Operand::Xmm(src)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::Sha256Msg2 {
                        dst: *dst,
                        src: *src,
                    });
                }
            }
            // === Phase H: RDPMC ===
            DecodedOpcode::Rdpmc => {
                ir.push(IrInstruction::Rdpmc { counter: 0 });
            }
            DecodedOpcode::Rdtsc => {
                ir.push(IrInstruction::Rdtsc);
            }
            // === Phase H: Cacheability instructions (no-ops on Apple Silicon) ===
            DecodedOpcode::Clflushopt => {
                ir.push(IrInstruction::Clflushopt { address: 0 });
            }
            DecodedOpcode::Clwb => {
                ir.push(IrInstruction::Clwb { address: 0 });
            }
            DecodedOpcode::Pcommit => {
                ir.push(IrInstruction::Pcommit);
            }
            // === Phase H: TSX/RTM transactional synchronization ===
            DecodedOpcode::Xbegin => {
                if let [Operand::ImmediateU64(target)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::Xbegin { target: *target });
                }
            }
            DecodedOpcode::Xend => {
                ir.push(IrInstruction::Xend);
            }
            DecodedOpcode::Xabort => {
                if let [Operand::ImmediateU64(imm)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::Xabort { imm: *imm as u8 });
                }
            }
            DecodedOpcode::Xtest => {
                ir.push(IrInstruction::Xtest);
            }
            // === Phase H: SGX stub detection ===
            DecodedOpcode::Encls => {
                ir.push(IrInstruction::Encls);
            }
            DecodedOpcode::Enclu => {
                ir.push(IrInstruction::Enclu);
            }
            // === Phase H: CET shadow stack instructions ===
            DecodedOpcode::Savesp => {
                // SAVESSP implicitly uses SSP register — address resolved at execute_ir
                ir.push(IrInstruction::SaveSsP { address: 0 });
            }
            DecodedOpcode::Rstorssp => {
                if let [Operand::Memory(address)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::Rstorssp { address: *address });
                }
            }
            DecodedOpcode::Incssp => {
                if let [Operand::Register(src)] = instruction.operands.as_slice() {
                    ir.push(IrInstruction::Incssp { src: *src });
                }
                // Memory-form INCSSP (extremely rare) is not emitted
            }
            DecodedOpcode::Wrss => {
                if let [Operand::Memory(address), Operand::Register(src)] =
                    instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::Wrss {
                        dst: *address,
                        src: *src,
                    });
                }
            }
            DecodedOpcode::Wruss => {
                if let [Operand::Memory(address), Operand::Register(src)] =
                    instruction.operands.as_slice()
                {
                    ir.push(IrInstruction::Wruss {
                        dst: *address,
                        src: *src,
                    });
                }
            }
            // === Phase H: MPX bounds checking ===
            DecodedOpcode::Bndmk => {
                if let [Operand::ImmediateU64(dst), src] = instruction.operands.as_slice() {
                    match src {
                        Operand::ImmediateU64(reg) => {
                            ir.push(IrInstruction::BndmkReg {
                                dst: *dst as u8,
                                src: *reg as u8,
                            });
                        }
                        Operand::Memory(addr) => {
                            ir.push(IrInstruction::BndmkMem {
                                dst: *dst as u8,
                                address: *addr,
                            });
                        }
                        _ => continue,
                    }
                }
            }
            DecodedOpcode::Bndcl => {
                if let [Operand::ImmediateU64(bnd), src] = instruction.operands.as_slice() {
                    match src {
                        Operand::ImmediateU64(reg) => {
                            ir.push(IrInstruction::BndclReg {
                                bnd: *bnd as u8,
                                src: *reg as u8,
                            });
                        }
                        Operand::Memory(addr) => {
                            ir.push(IrInstruction::BndclMem {
                                bnd: *bnd as u8,
                                address: *addr,
                            });
                        }
                        _ => continue,
                    }
                }
            }
            DecodedOpcode::Bndcu => {
                if let [Operand::ImmediateU64(bnd), src] = instruction.operands.as_slice() {
                    match src {
                        Operand::ImmediateU64(reg) => {
                            ir.push(IrInstruction::BndcuReg {
                                bnd: *bnd as u8,
                                src: *reg as u8,
                            });
                        }
                        Operand::Memory(addr) => {
                            ir.push(IrInstruction::BndcuMem {
                                bnd: *bnd as u8,
                                address: *addr,
                            });
                        }
                        _ => continue,
                    }
                }
            }
            DecodedOpcode::Bndcn => {
                if let [Operand::ImmediateU64(bnd), src] = instruction.operands.as_slice() {
                    match src {
                        Operand::ImmediateU64(reg) => {
                            ir.push(IrInstruction::BndcnReg {
                                bnd: *bnd as u8,
                                src: *reg as u8,
                            });
                        }
                        Operand::Memory(addr) => {
                            ir.push(IrInstruction::BndcnMem {
                                bnd: *bnd as u8,
                                address: *addr,
                            });
                        }
                        _ => continue,
                    }
                }
            }
            DecodedOpcode::Bndmov => {
                if let [Operand::ImmediateU64(dst), src, rest @ ..] =
                    instruction.operands.as_slice()
                {
                    let direction = rest
                        .first()
                        .and_then(|o| {
                            if let Operand::ImmediateU64(v) = o {
                                Some(*v)
                            } else {
                                None
                            }
                        })
                        .unwrap_or(0);
                    if direction == 0 {
                        // Load form
                        match src {
                            Operand::ImmediateU64(src_reg) => {
                                ir.push(IrInstruction::BndmovReg {
                                    dst: *dst as u8,
                                    src: *src_reg as u8,
                                });
                            }
                            Operand::Memory(addr) => {
                                ir.push(IrInstruction::BndmovMemLoad {
                                    dst: *dst as u8,
                                    address: *addr,
                                });
                            }
                            _ => continue,
                        }
                    } else {
                        // Store form (not yet produced by decoder, but handled for completeness)
                        if let Operand::Memory(addr) = src {
                            ir.push(IrInstruction::BndmovMemStore {
                                src: *dst as u8,
                                address: *addr,
                            });
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Ok(ir)
}

#[allow(dead_code)] // ARM64 lowering prototype; superseded by the JIT backend
pub(crate) fn lower_to_arm64(ir: &[IrInstruction]) -> Vec<String> {
    let mut instructions = Vec::new();
    for op in ir {
        match op {
            IrInstruction::Cpuid => instructions.push("bl __casa1_cpuid".to_string()),
            IrInstruction::Xgetbv => instructions.push("bl __casa1_xgetbv".to_string()),
            IrInstruction::MovImm { dst, value } => {
                instructions.push(format!("movz x{}, #{:#x}", dst.index(), value & 0xffff));
            }
            IrInstruction::MovImm8 { dst, value } => {
                instructions.push(format!("mov w{}, #{:#x}", dst.full_register().index(), value));
            }
            IrInstruction::MovReg { dst, src, width } => {
                let register_class = if *width == 8 { 'x' } else { 'w' };
                instructions.push(format!("mov {register_class}{}, {register_class}{}", dst.index(), src.index()));
            }
            IrInstruction::MovReg8 { dst, src } => {
                instructions.push(format!("mov w{}, w{}", dst.full_register().index(), src.full_register().index()));
            }
            IrInstruction::AddImm { dst, value, .. } => {
                instructions.push(format!("add x{}, x{}, #{:#x}", dst.index(), dst.index(), value));
            }
            IrInstruction::AdcImm { dst, value, .. } => {
                instructions.push(format!("adcs x{}, x{}, #{:#x}", dst.index(), dst.index(), value));
            }
            IrInstruction::AdcImm8 { dst, value } => {
                instructions.push(format!("adcs w{}, w{}, #{:#x}", dst.full_register().index(), dst.full_register().index(), value));
            }
            IrInstruction::AddOperand { dst, .. } => {
                instructions.push(format!("add x{}, x{}, xadd_src", dst.index(), dst.index()));
            }
            IrInstruction::AddMemory { src, .. } => {
                instructions.push(format!("ldr xtmp, [mem]; add xtmp, xtmp, x{}; str xtmp, [mem]", src.index()));
            }
            IrInstruction::AddImmMemory { value, .. } => {
                instructions.push(format!("ldr xtmp, [mem]; add xtmp, xtmp, #{value:#x}; str xtmp, [mem]"));
            }
            IrInstruction::AdcOperand { dst, .. } => {
                instructions.push(format!("adc x{}, x{}, xadc_src", dst.index(), dst.index()));
            }
            IrInstruction::AdcImmMemory { value, .. } => {
                instructions.push(format!("ldr xtmp, [mem]; adcs xtmp, xtmp, #{value:#x}; str xtmp, [mem]"));
            }
            // ADX instructions: JIT stubs (software-assisted interpreter fallback)
            IrInstruction::Adcx { dst, .. } | IrInstruction::Adox { dst, .. } => {
                instructions.push(format!("// ADX {}(interpreter only)", dst.index()));
            }
            IrInstruction::AndReg { dst, .. } => {
                instructions.push(format!("and x{}, x{}, xand_src", dst.index(), dst.index()));
            }
            IrInstruction::AndMemory { .. } => {
                instructions.push("and xand_addr, xand_addr, xand_src".to_string());
            }
            IrInstruction::NotMemory { .. } => {
                instructions.push("mvn wtmp, wtmp_mem; str wtmp, [mem]".to_string());
            }
            IrInstruction::OrImm { dst, value, .. } => {
                instructions.push(format!("orr x{}, x{}, #{:#x}", dst.index(), dst.index(), value));
            }
            IrInstruction::OrImm8 { dst, value } => {
                instructions.push(format!("orr w{}, w{}, #{:#x}", dst.full_register().index(), dst.full_register().index(), value));
            }
            IrInstruction::AndImm8 { dst, value } => {
                instructions.push(format!("and w{}, w{}, #{:#x}", dst.full_register().index(), dst.full_register().index(), value));
            }
            IrInstruction::OrImmMemory { value, .. } => {
                instructions.push(format!("ldr xtmp, [mem]; orr xtmp, xtmp, #{value:#x}; str xtmp, [mem]"));
            }
            IrInstruction::SubImm { dst, value, .. } => {
                instructions.push(format!("sub x{}, x{}, #{:#x}", dst.index(), dst.index(), value));
            }
            IrInstruction::SubImmMemory { value, .. } => {
                instructions.push(format!("ldr xtmp, [mem]; sub xtmp, xtmp, #{value:#x}; str xtmp, [mem]"));
            }
            IrInstruction::SbbMemory { .. } => {
                instructions.push("sbc smem, smem, xsrc".to_string());
            }
            IrInstruction::SbbOperand { dst, .. } => {
                instructions.push(format!("sbc x{}, x{}, xsrc", dst.index(), dst.index()));
            }
            IrInstruction::AndImm { dst, value, .. } => {
                instructions.push(format!("and x{}, x{}, #{:#x}", dst.index(), dst.index(), value));
            }
            IrInstruction::AndImmMemory { value, .. } => {
                instructions.push(format!("ldr xtmp, [mem]; and xtmp, xtmp, #{value:#x}; str xtmp, [mem]"));
            }
            IrInstruction::RolImm { dst, count, .. } => {
                instructions.push(format!("rol x{}, x{}, #{}", dst.index(), dst.index(), count));
            }
            IrInstruction::RolImmMemory { count, .. } => {
                instructions.push(format!("rol xrol_addr, xrol_addr, #{}", count));
            }
            IrInstruction::ShlImm { dst, count, .. } => {
                instructions.push(format!("lsl x{}, x{}, #{count}", dst.index(), dst.index()));
            }
            IrInstruction::ShlImmMemory { count, .. } => {
                instructions.push(format!("lsl xshl_addr, xshl_addr, #{count}"));
            }
            IrInstruction::ShrImm { dst, count, .. } => {
                instructions.push(format!("lsr x{}, x{}, #{count}", dst.index(), dst.index()));
            }
            IrInstruction::ShrImmMemory { count, .. } => {
                instructions.push(format!("lsr xshr_addr, xshr_addr, #{count}"));
            }
            IrInstruction::RolCl { dst, .. } => {
                instructions.push(format!("rol x{}, x{}, xcl", dst.index(), dst.index()));
            }
            IrInstruction::SarImm { dst, count, .. } => {
                instructions.push(format!("asr x{}, x{}, #{count}", dst.index(), dst.index()));
            }
            IrInstruction::SarImmMemory { count, .. } => {
                instructions.push(format!("asr xsar_addr, xsar_addr, #{count}"));
            }
            IrInstruction::ShlCl { dst, .. } => {
                instructions.push(format!("lsl x{}, x{}, wcl", dst.index(), dst.index()));
            }
            IrInstruction::ShldImm { dst, src, count, .. } => {
                instructions.push(format!("shld x{}, x{}, x{}, #{count}", dst.index(), dst.index(), src.index()));
            }
            IrInstruction::ShldCl { dst, src, .. } => {
                instructions.push(format!("shld x{}, x{}, x{}, wcl", dst.index(), dst.index(), src.index()));
            }
            IrInstruction::ShrdImm { dst, src, count, .. } => {
                instructions.push(format!("shrd x{}, x{}, x{}, #{count}", dst.index(), dst.index(), src.index()));
            }
            IrInstruction::ShrCl { dst, .. } => {
                instructions.push(format!("lsr x{}, x{}, wcl", dst.index(), dst.index()));
            }
            IrInstruction::SarCl { dst, .. } => {
                instructions.push(format!("asr x{}, x{}, wcl", dst.index(), dst.index()));
            }
            IrInstruction::RorCl { dst, .. } => {
                instructions.push(format!("ror x{}, x{}, xcl", dst.index(), dst.index()));
            }
            IrInstruction::ImulImm { dst, imm, .. } => {
                instructions.push(format!("mul x{}, ximul_src, #{imm:#x}", dst.index()));
            }
            IrInstruction::ImulReg { dst, .. } => {
                instructions.push(format!("mul x{}, x{}, ximul_src", dst.index(), dst.index()));
            }
            IrInstruction::MulAcc { .. } => {
                instructions.push("umull xmul_lo, w0, wmul_src".to_string());
            }
            IrInstruction::ImulAcc { .. } => {
                instructions.push("smull xmul_lo, w0, wimul_src".to_string());
            }
            IrInstruction::Div { .. } => {
                instructions.push("udiv div_acc, div_src".to_string());
            }
            IrInstruction::Idiv { .. } => {
                instructions.push("sdiv div_acc, div_src".to_string());
            }
            IrInstruction::SubReg8 { dst, .. } => {
                instructions.push(format!(
                    "sub w{}, w{}, wsub8_src",
                    dst.full_register().index(),
                    dst.full_register().index()
                ));
            }
            IrInstruction::SbbReg8 { dst, .. } => {
                instructions.push(format!(
                    "sbc w{}, w{}, wsbb8_src",
                    dst.full_register().index(),
                    dst.full_register().index()
                ));
            }
            IrInstruction::IncReg8 { dst } => {
                instructions.push(format!("add w{}, w{}, #1", dst.full_register().index(), dst.full_register().index()));
            }
            IrInstruction::DecReg8 { dst } => {
                instructions.push(format!("sub w{}, w{}, #1", dst.full_register().index(), dst.full_register().index()));
            }
            IrInstruction::IncMemory { .. } => {
                instructions.push("add xinc_addr, xinc_addr, #1".to_string());
            }
            IrInstruction::DecMemory { .. } => {
                instructions.push("sub xdec_addr, xdec_addr, #1".to_string());
            }
            IrInstruction::NegReg { dst, .. } => {
                instructions.push(format!("neg x{}", dst.index()));
            }
            IrInstruction::NegReg8 { dst } => {
                instructions.push(format!("neg w{}", dst.full_register().index()));
            }
            IrInstruction::NotReg { dst, .. } => {
                instructions.push(format!("mvn x{}, x{}", dst.index(), dst.index()));
            }
            IrInstruction::NotReg8 { dst } => {
                instructions.push(format!("mvn w{}, w{}", dst.full_register().index(), dst.full_register().index()));
            }
            IrInstruction::Movs { repeat, .. } => {
                instructions.push(if *repeat {
                    "bl __casa1_rep_movs".to_string()
                } else {
                    "bl __casa1_movs".to_string()
                });
            }
            IrInstruction::Stos { repeat, .. } => {
                instructions.push(if *repeat {
                    "bl __casa1_rep_stos".to_string()
                } else {
                    "bl __casa1_stos".to_string()
                });
            }
            IrInstruction::Cdq { .. } => {
                instructions.push("bl __casa1_cdq".to_string());
            }
            IrInstruction::SubOperand { dst, .. } => {
                instructions.push(format!("sub x{}, x{}, xsub_src", dst.index(), dst.index()));
            }
            IrInstruction::SubMemory { .. } => {
                instructions.push("sub xsub_addr, xsub_addr, xsub_src".to_string());
            }
            IrInstruction::Compare { .. } => instructions.push("cmp xcmp_lhs, xcmp_rhs".to_string()),
            IrInstruction::Test { .. } => instructions.push("tst xtest_lhs, xtest_rhs".to_string()),
            IrInstruction::ExchangeRegisters { left, right, .. } => {
                instructions.push(format!("mov xtmp, x{}; mov x{}, x{}; mov x{}, xtmp", left.index(), left.index(), right.index(), right.index()));
            }
            IrInstruction::ExchangeRegisters8 { left, right } => {
                instructions.push(format!("// xchg b{}, b{} (byte regs, interpreter only)", left.full_register().index(), right.full_register().index()));
            }
            IrInstruction::ExchangeMemory8 { reg, .. } => {
                instructions.push(format!("// xchg b{}, [mem] (byte reg, interpreter only)", reg.full_register().index()));
            }
            IrInstruction::ExchangeMemory { .. } => instructions.push("swp xswap_src, xswap_dst, [mem]".to_string()),
            IrInstruction::SignExtendTo64 { dst, .. } => {
                instructions.push(format!("sxtw x{}, wsrc", dst.index()));
            }
            IrInstruction::SignExtend { dst, .. } => {
                instructions.push(format!("sxt x{}, wsrc", dst.index()));
            }
            IrInstruction::ZeroExtendTo64 { dst, .. } => {
                instructions.push(format!("uxtw x{}, wsrc", dst.index()));
            }
            IrInstruction::AddReg8 { dst, src } => {
                instructions.push(format!(
                    "add w{}, w{}, w{}",
                    dst.full_register().index(),
                    dst.full_register().index(),
                    src.full_register().index()
                ));
            }
            IrInstruction::AddReg8Op { dst, .. } => {
                instructions.push(format!(
                    "// AddReg8Op w{} (interpreter only)",
                    dst.full_register().index()
                ));
            }
            IrInstruction::AdcReg8 { dst, src } => {
                instructions.push(format!(
                    "adc w{}, w{}, w{}",
                    dst.full_register().index(),
                    dst.full_register().index(),
                    src.full_register().index()
                ));
            }
            IrInstruction::AdcReg8Op { dst, .. } => {
                instructions.push(format!(
                    "// AdcReg8Op w{} (interpreter only)",
                    dst.full_register().index()
                ));
            }
            IrInstruction::XorImm { dst, value, .. } => {
                instructions.push(format!("eor x{}, x{}, #{:#x}", dst.index(), dst.index(), value));
            }
            IrInstruction::XorImmMemory { value, .. } => {
                instructions.push(format!("ldr xtmp, [mem]; eor xtmp, xtmp, #{value:#x}; str xtmp, [mem]"));
            }
            IrInstruction::XorReg { dst, .. } => {
                instructions.push(format!("eor x{}, x{}, xxor_src", dst.index(), dst.index()));
            }
            IrInstruction::XorReg8 { dst, src } => {
                instructions.push(format!(
                    "eor w{}, w{}, w{}",
                    dst.full_register().index(),
                    dst.full_register().index(),
                    src.full_register().index()
                ));
            }
            IrInstruction::XorReg8Op { dst, .. } => {
                instructions.push(format!(
                    "// XorReg8Op w{} (interpreter only)",
                    dst.full_register().index()
                ));
            }
            IrInstruction::XorMemory { src, .. } => {
                instructions.push(format!("ldr xtmp, [mem]; eor xtmp, xtmp, x{}; str xtmp, [mem]", src.index()));
            }
            IrInstruction::AndReg8 { dst, src } => {
                instructions.push(format!(
                    "and w{}, w{}, w{}",
                    dst.full_register().index(),
                    dst.full_register().index(),
                    src.full_register().index()
                ));
            }
            IrInstruction::AndReg8Op { dst, .. } => {
                instructions.push(format!(
                    "// AndReg8Op w{} (interpreter only)",
                    dst.full_register().index()
                ));
            }
            IrInstruction::BitTest { base, bit, .. } => {
                instructions.push(format!("ubfx xcf, x{}, x{}, #1", base.index(), bit.index()));
            }
            IrInstruction::BitTestImm { src, bit, .. } => match src {
                CompareOperand::Register(base) => {
                    instructions.push(format!("ubfx xcf, x{}, #{bit}, #1", base.index()));
                }
                CompareOperand::Memory(_) => {
                    instructions.push(format!("ldr xtmp, [mem]; ubfx xcf, xtmp, #{bit}, #1"));
                }
                _ => {
                    instructions.push(format!("bt_imm #{bit}"));
                }
            },
            IrInstruction::OrReg { dst, .. } => {
                instructions.push(format!("orr x{}, x{}, xorr_src", dst.index(), dst.index()));
            }
            IrInstruction::OrMemory { src, .. } => {
                instructions.push(format!("ldr xtmp, [mem]; orr xtmp, xtmp, x{}; str xtmp, [mem]", src.index()));
            }
            IrInstruction::OrMemory8 { src, .. } => {
                instructions.push(format!("ldrb wtmp, [mem]; orr wtmp, wtmp, w{}; strb wtmp, [mem]", src.full_register().index()));
            }
            IrInstruction::OrReg8 { dst, src } => {
                instructions.push(format!(
                    "orr w{}, w{}, w{}",
                    dst.full_register().index(),
                    dst.full_register().index(),
                    src.full_register().index()
                ));
            }
            IrInstruction::OrReg8Op { dst, .. } => {
                instructions.push(format!(
                    "// OrReg8Op w{} (interpreter only)",
                    dst.full_register().index()
                ));
            }
            IrInstruction::IncReg { dst, .. } => {
                instructions.push(format!("add x{}, x{}, #1", dst.index(), dst.index()));
            }
            IrInstruction::DecReg { dst, .. } => {
                instructions.push(format!("sub x{}, x{}, #1", dst.index(), dst.index()));
            }
            IrInstruction::Cmov { dst, .. } => {
                instructions.push(format!("csel x{}, xcmov_src, x{}, eq", dst.index(), dst.index()));
            }
            IrInstruction::LoadMemory8 { dst, .. } => {
                instructions.push(format!("ldrb w{}, [mem]", dst.full_register().index()));
            }
            IrInstruction::LoadMemory { dst, .. } => {
                instructions.push(format!("ldr x{}, [mem]", dst.index()));
            }
            IrInstruction::StoreMemory8 { src, .. } => {
                instructions.push(format!("strb w{}, [mem]", src.full_register().index()));
            }
            IrInstruction::StoreMemory { src, .. } => {
                instructions.push(format!("str x{}, [mem]", src.index()));
            }
            IrInstruction::StoreImmediate { value, width, .. } => {
                instructions.push(format!("mov imm_store_{width}, #{value:#x}"));
            }
            IrInstruction::Call { target, .. } => {
                instructions.push(format!("bl {target:#x}"));
            }
            IrInstruction::CallRegister { src, .. } => {
                instructions.push(format!("blr x{}", src.index()));
            }
            IrInstruction::CallMemory { .. } => {
                instructions.push("blr xmem_target".to_string());
            }
            IrInstruction::JumpRegister { src } => {
                instructions.push(format!("br x{}", src.index()));
            }
            IrInstruction::JumpMemory { .. } => {
                instructions.push("br xmem_target".to_string());
            }
            IrInstruction::Setcc { dst, .. } => {
                instructions.push(format!("cset w{}, eq", dst.full_register().index()));
            }
            IrInstruction::SetccMemory { .. } => {
                instructions.push("cset wtmp, eq; strb wtmp, [mem]".to_string());
            }
            IrInstruction::JumpIf { target, .. } => instructions.push(format!("b.cond {target:#x}")),
            IrInstruction::Jump { target } => instructions.push(format!("b {target:#x}")),
            IrInstruction::Nop => instructions.push("nop".to_string()),
            IrInstruction::LoadEffectiveAddress { dst, .. } => {
                instructions.push(format!("add x{}, xzr, #lea", dst.index()));
            }
            IrInstruction::PushReg { src } => {
                instructions.push(format!("str x{}, [sp, #-8]!", src.index()));
            }
            IrInstruction::PushMemory { width, .. } => {
                instructions.push(format!("push_mem{width}"));
            }
            IrInstruction::PushImm { value, width } => {
                instructions.push(format!("push{width} #{value:#x}"));
            }
            IrInstruction::PopSeg { width } => {
                instructions.push(format!("add sp, sp, #{width}"));
            }
            IrInstruction::PushFlags { width } => {
                instructions.push(format!("pushf{width}"));
            }
            IrInstruction::PopReg { dst } => {
                instructions.push(format!("ldr x{}, [sp], #8", dst.index()));
            }
            IrInstruction::PopMemory { width, .. } => {
                instructions.push(format!("pop_mem{width}"));
            }
            IrInstruction::PopFlags { width } => {
                instructions.push(format!("popf{width}"));
            }
            IrInstruction::Cld => {
                instructions.push("cld".to_string());
            }
            IrInstruction::Leave => {
                instructions.push("leave".to_string());
            }
            IrInstruction::Return { stack_adjust } => {
                if *stack_adjust == 0 {
                    instructions.push("ret".to_string());
                } else {
                    instructions.push(format!("ret #{stack_adjust:#x}"));
                }
            }
            IrInstruction::Popcnt { dst, src } => {
                instructions.push(format!("cnt x{}, x{}", dst.index(), src.index()));
            }
            IrInstruction::Lzcnt { dst, src } => {
                instructions.push(format!("clz x{}, x{}", dst.index(), src.index()));
            }
            IrInstruction::Bsf { dst, src } => {
                instructions.push(format!("bsf x{}, x{}", dst.index(), src.index()));
            }
            IrInstruction::MovdToXmm { dst, src } => {
                instructions.push(format!("movd v{dst}.4s, w{}", src.index()));
            }
            IrInstruction::MovdFromXmm { dst, src } => {
                instructions.push(format!("mov w{}, v{src}.s[0]", dst.index()));
            }
            IrInstruction::StoreDwordFromXmm { address: _, src } => {
                instructions.push(format!("str wtmp_from_v{src}, [mem]"));
            }
            IrInstruction::Pshufd { dst, src, imm } => {
                instructions.push(format!("pshufd v{dst}.4s, v{src}.4s, #0x{imm:02x}"));
            }
            IrInstruction::Pshuflw { dst, src, imm } => {
                instructions.push(format!("pshuflw v{dst}.8h, v{src}.8h, #0x{imm:02x}"));
            }
            IrInstruction::Psrldq { dst, imm } => {
                instructions.push(format!("psrldq v{dst}.16b, #0x{imm:02x}"));
            }
            IrInstruction::Pslldq { dst, imm } => {
                instructions.push(format!("pslldq v{dst}.16b, #0x{imm:02x}"));
            }
            IrInstruction::Movlhps { dst, src } => {
                instructions.push(format!("movlhps v{dst}.16b, v{src}.16b"));
            }
            IrInstruction::MoveXmm { dst, src } => {
                instructions.push(format!("mov v{dst}.16b, v{src}.16b"));
            }
            IrInstruction::LoadXmm { dst, .. } => {
                instructions.push(format!("ldr q{dst}, [mem]"));
            }
            IrInstruction::StoreXmm { src, .. } => {
                instructions.push(format!("str q{src}, [mem]"));
            }
            IrInstruction::MoveVector { dst, src, width } => {
                instructions.push(format!("mov vector{width} v{dst}, v{src}"));
            }
            IrInstruction::LoadVector { dst, width, .. } => {
                instructions.push(format!("ldr vector{width} v{dst}, [mem]"));
            }
            IrInstruction::StoreVector { src, width, .. } => {
                instructions.push(format!("str vector{width} v{src}, [mem]"));
            }
            IrInstruction::Pxor { dst, src } => {
                instructions.push(format!("eor v{dst}.16b, v{dst}.16b, v{src}.16b"));
            }
            IrInstruction::VectorOr { dst, lhs, rhs, width } => match rhs {
                VectorOperand::Register(src) => {
                    instructions.push(format!("orr vector{width} v{dst}.16b, v{lhs}.16b, v{src}.16b"));
                }
                VectorOperand::Memory(_) => {
                    instructions.push(format!("ldr vector{width} vtmp, [mem]; orr vector{width} v{dst}.16b, v{lhs}.16b, vtmp.16b"));
                }
            },
            IrInstruction::VectorXor { dst, lhs, rhs, width } => match rhs {
                VectorOperand::Register(src) => {
                    instructions.push(format!("eor vector{width} v{dst}, v{lhs}, v{src}"));
                }
                VectorOperand::Memory(_) => {
                    instructions.push(format!("ldr vector{width} vtmp, [mem]; eor vector{width} v{dst}, v{lhs}, vtmp"));
                }
            },
            IrInstruction::VectorCompareEqBytes { dst, lhs, rhs, width } => match rhs {
                VectorOperand::Register(src) => {
                    instructions.push(format!("cmeq vector{width} v{dst}.16b, v{lhs}.16b, v{src}.16b"));
                }
                VectorOperand::Memory(_) => {
                    instructions.push(format!("ldr vector{width} vtmp, [mem]; cmeq vector{width} v{dst}.16b, v{lhs}.16b, vtmp.16b"));
                }
            },
            IrInstruction::VectorMoveMaskBytes { dst, src, width } => {
                instructions.push(format!("movmask{width} x{}, v{src}", dst.index()));
            }
            IrInstruction::Paddq { dst, src } => {
                instructions.push(format!("add v{dst}.2d, v{dst}.2d, v{src}.2d"));
            }
            IrInstruction::Paddd { dst, src } => {
                instructions.push(format!("add v{dst}.4s, v{dst}.4s, v{src}.4s"));
            }
            IrInstruction::Pmulld { dst, src } => {
                instructions.push(format!("mul v{dst}.4s, v{dst}.4s, v{src}.4s"));
            }
            IrInstruction::Psubd { dst, src } => {
                instructions.push(format!("sub v{dst}.4s, v{dst}.4s, v{src}.4s"));
            }
            IrInstruction::VectorAddQ { dst, lhs, rhs, width } => match rhs {
                VectorOperand::Register(src) => {
                    instructions.push(format!("add vector{width} v{dst}, v{lhs}, v{src}"));
                }
                VectorOperand::Memory(_) => {
                    instructions.push(format!("ldr vector{width} vtmp, [mem]; add vector{width} v{dst}, v{lhs}, vtmp"));
                }
            },
            IrInstruction::VzeroUpper => instructions.push("bl __casa1_vzeroupper".to_string()),
            IrInstruction::X87ClearExceptions => instructions.push("bl __casa1_x87_clear_exceptions".to_string()),
            IrInstruction::X87LoadInt32 { .. } => instructions.push("bl __casa1_x87_fild_i32".to_string()),
            IrInstruction::X87LoadInt64 { .. } => instructions.push("bl __casa1_x87_fild_i64".to_string()),
            IrInstruction::X87Load { width, .. } => {
                instructions.push(match *width {
                    4 => "bl __casa1_x87_load_f32".to_string(),
                    _ => "bl __casa1_x87_load_f64".to_string(),
                })
            }
            IrInstruction::X87LoadControlWord { .. } => {
                instructions.push("bl __casa1_x87_load_control_word".to_string())
            }
            IrInstruction::X87NegateTop => instructions.push("bl __casa1_x87_fchs".to_string()),
            IrInstruction::X87AddMemory { width, .. } => {
                instructions.push(match *width {
                    4 => "bl __casa1_x87_fadd_m32".to_string(),
                    _ => "bl __casa1_x87_fadd_m64".to_string(),
                })
            }
            IrInstruction::X87MulMemory { width, .. } => {
                instructions.push(match *width {
                    4 => "bl __casa1_x87_fmul_m32".to_string(),
                    _ => "bl __casa1_x87_fmul_m64".to_string(),
                })
            }
            IrInstruction::X87DivMemory { width, .. } => {
                instructions.push(match *width {
                    4 => "bl __casa1_x87_fdiv_m32".to_string(),
                    _ => "bl __casa1_x87_fdiv_m64".to_string(),
                })
            }
            IrInstruction::X87Swap { index, .. } => {
                instructions.push(format!("bl __casa1_x87_fxch_st{}", index))
            }
            IrInstruction::X87StoreControlWord { .. } => {
                instructions.push("bl __casa1_x87_store_control_word".to_string())
            }
            IrInstruction::X87Store { width, pop, .. } => {
                instructions.push(match (*width, *pop) {
                    (4, false) => "bl __casa1_x87_store_f32".to_string(),
                    (4, true) => "bl __casa1_x87_store_pop_f32".to_string(),
                    (8, false) => "bl __casa1_x87_store_f64".to_string(),
                    _ => "bl __casa1_x87_store_pop".to_string(),
                })
            }
            IrInstruction::X87StorePopRegister { index } => {
                instructions.push(format!("bl __casa1_x87_fstp_st{}", index))
            }
            IrInstruction::X87StorePop { .. } => {
                instructions.push("bl __casa1_x87_store_pop".to_string())
            }
            IrInstruction::X87Compare { index, pop } => {
                instructions.push(format!("bl __casa1_x87_fcom{}st{}", if *pop { "p_" } else { "_" }, index))
            }
            IrInstruction::X87Init => instructions.push("bl __casa1_x87_init".to_string()),
            IrInstruction::LoadMxcsr { .. } => instructions.push("bl __casa1_load_mxcsr".to_string()),
            IrInstruction::StoreMxcsr { .. } => instructions.push("bl __casa1_store_mxcsr".to_string()),
            IrInstruction::X87AddPop { index } => {
                instructions.push(format!("bl __casa1_x87_faddp_st{}", index))
            }
            IrInstruction::X87Mul { index } => {
                instructions.push(format!("bl __casa1_x87_fmul_st{}", index))
            }
            IrInstruction::X87DivRegister { index } => {
                instructions.push(format!("bl __casa1_x87_fdiv_st{}", index))
            }
            IrInstruction::X87DivPop { index } => {
                instructions.push(format!("bl __casa1_x87_fdivp_st{}", index))
            }
            IrInstruction::Cvtpd2ps { dst, src } => match src {
                VectorOperand::Register(src) => {
                    instructions.push(format!("fcvtn v{dst}.2s, v{src}.2d"));
                }
                VectorOperand::Memory(_) => {
                    instructions.push(format!("ldr qtmp, [mem]; fcvtn v{dst}.2s, vtmp.2d"));
                }
            },
            IrInstruction::Cvtdq2pd { dst, src } => match src {
                VectorOperand::Register(src) => {
                    instructions.push(format!("cvtdq2pd v{dst}.2d, v{src}.2s"));
                }
                VectorOperand::Memory(_) => {
                    instructions.push(format!("ldr dtmp, [mem]; scvtf v{dst}.2d, vtmp.2s"));
                }
            },
            IrInstruction::Addsd { dst, src } => match src {
                VectorOperand::Register(src) => {
                    instructions.push(format!("fadd d{dst}, d{dst}, d{src}"));
                }
                VectorOperand::Memory(_) => {
                    instructions.push(format!("ldr dtmp, [mem]; fadd d{dst}, d{dst}, dtmp"));
                }
            },
            IrInstruction::Divss { dst, src } => match src {
                VectorOperand::Register(src) => {
                    instructions.push(format!("fdiv s{dst}, s{dst}, s{src}"));
                }
                VectorOperand::Memory(_) => {
                    instructions.push(format!("ldr stmp, [mem]; fdiv s{dst}, s{dst}, stmp"));
                }
            },
            IrInstruction::Comiss { lhs, rhs } => match rhs {
                VectorOperand::Register(rhs) => {
                    instructions.push(format!("fcmp s{lhs}, s{rhs}"));
                }
                VectorOperand::Memory(_) => {
                    instructions.push(format!("ldr stmp, [mem]; fcmp s{lhs}, stmp"));
                }
            },
            IrInstruction::Pcmpistri { lhs, rhs, imm } => match rhs {
                VectorOperand::Register(rhs) => {
                    instructions.push(format!("pcmpistri xmm{lhs}, xmm{rhs}, #0x{imm:02x}"));
                }
                VectorOperand::Memory(_) => {
                    instructions.push(format!("pcmpistri xmm{lhs}, [mem], #0x{imm:02x}"));
                }
            },
            IrInstruction::HaddPs { dst, src } => {
                instructions.push(format!("faddp v{dst}.4s, v{dst}.4s, v{src}.4s"));
            }
            IrInstruction::Pshufb { dst, mask } => {
                instructions.push(format!("tbl v{dst}.16b, {{v{dst}.16b}}, v{mask}.16b"));
            }
            IrInstruction::BlendD { dst, src, mask } => {
                instructions.push(format!("bsl v{dst}.16b, v{src}.16b, #0x{mask:02x}"));
            }
            IrInstruction::Crc32 { dst, src } => {
                instructions.push(format!("crc32x w{}, w{}, x{}", dst.index(), dst.index(), src.index()));
            }
            IrInstruction::Andn { dst, lhs, rhs } => {
                instructions.push(format!("bic x{}, x{}, x{}", dst.index(), rhs.index(), lhs.index()));
            }
            IrInstruction::Pdep { dst, .. } => {
                instructions.push(format!("bl __casa1_pdep -> x{}", dst.index()));
            }
            IrInstruction::Pext { dst, .. } => {
                instructions.push(format!("bl __casa1_pext -> x{}", dst.index()));
            }
            IrInstruction::Rdrand { dst } => {
                instructions.push(format!("bl __casa1_rdrand -> x{}", dst.index()));
            }
            IrInstruction::Rdseed { dst } => {
                instructions.push(format!("bl __casa1_rdseed -> x{}", dst.index()));
            }
            IrInstruction::Bextr { dst, src, range } => {
                instructions.push(format!("ubfx x{}, x{}, x{}, #0", dst.index(), src.index(), range.index()));
            }
            IrInstruction::Blsi { dst, src } => {
                instructions.push(format!("neg x9, x{}", src.index()));
                instructions.push(format!("and x{}, x{}, x9", dst.index(), src.index()));
            }
            IrInstruction::Blsmsk { dst, src } => {
                instructions.push(format!("sub x9, x{}, #1", src.index()));
                instructions.push(format!("eor x{}, x{}, x9", dst.index(), src.index()));
            }
            IrInstruction::Blsr { dst, src } => {
                instructions.push(format!("sub x9, x{}, #1", src.index()));
                instructions.push(format!("and x{}, x{}, x9", dst.index(), src.index()));
            }
            IrInstruction::Bzhi { dst, src, index } => {
                instructions.push(format!("lsl x9, x{}, #56", index.index()));
                instructions.push("lsr x9, x9, #56".to_string());
                instructions.push("cmp x9, #64".to_string());
                instructions.push("csel x9, x9, xzr, lo".to_string());
                instructions.push("lsl x10, xzr, x9".to_string());
                instructions.push("sub x10, x10, #1".to_string());
                instructions.push(format!("and x{}, x{}, x10", dst.index(), src.index()));
            }
            IrInstruction::Mulx { dst_lo, dst_hi, src } => {
                instructions.push(format!("umulh x{}, x{}, x{}", dst_hi.index(), Register::Rdx.index(), src.index()));
                instructions.push(format!("mul x{}, x{}, x{}", dst_lo.index(), Register::Rdx.index(), src.index()));
            }
            IrInstruction::Rorx { dst, src, imm } => {
                instructions.push(format!("ror x{}, x{}, #{}", dst.index(), src.index(), imm));
            }
            IrInstruction::Sarx { dst, src, shift } => {
                instructions.push(format!("asr x{}, x{}, x{}", dst.index(), src.index(), shift.index()));
            }
            IrInstruction::Shrx { dst, src, shift } => {
                instructions.push(format!("lsr x{}, x{}, x{}", dst.index(), src.index(), shift.index()));
            }
            IrInstruction::Shlx { dst, src, shift } => {
                instructions.push(format!("lsl x{}, x{}, x{}", dst.index(), src.index(), shift.index()));
            }
            IrInstruction::LockCmpxchg { .. } => instructions.push("bl __casa1_cmpxchg".to_string()),
            IrInstruction::LockCmpxchg8b { .. } => instructions.push("bl __casa1_cmpxchg8b".to_string()),
            IrInstruction::LockXadd { .. } => {
                instructions.push("ldaxr x9, [mem]".to_string());
                instructions.push("stlxr w10, x11, [mem]".to_string());
            }
            IrInstruction::Mfence => instructions.push("dmb ish".to_string()),
            IrInstruction::X87LoadConst { .. } => instructions.push("bl __casa1_x87_push".to_string()),
            IrInstruction::X87Add => instructions.push("bl __casa1_x87_add".to_string()),
            IrInstruction::X87Div => instructions.push("bl __casa1_x87_div".to_string()),
            IrInstruction::FmaVector { kind, dst, src1, src2, element_kind, width } => {
                // ARM64 FMA: use fmla (fused multiply-add) when possible
                let suffix = match (element_kind, width) {
                    (0, 8) => "2s",
                    (0, 16) => "4s",
                    (0, 32) => "8s",
                    (1, 8) => "1d",
                    (1, 16) => "2d",
                    (1, 32) => "4d",
                    _ => "16b",
                };
                let src2_str = match src2 {
                    VectorOperand::Register(r) => format!("v{r}.{suffix}"),
                    VectorOperand::Memory(_) => "[mem]".to_string(),
                };
                let kind_str = match kind {
                    FmaKind::Vfmadd132 | FmaKind::Vfmadd213 => "mla",
                    FmaKind::Vfmadd231 => "mla",
                    FmaKind::Vfmsub132 | FmaKind::Vfmsub213 => "mls",
                    FmaKind::Vfmsub231 => "mls",
                    FmaKind::Vfnmadd132 | FmaKind::Vfnmadd213 => "fmla",
                    FmaKind::Vfnmadd231 => "fmla",
                };
                instructions.push(format!(
                    "// FMA: v{dst}.{suffix}, v{src1}.{suffix}, {src2_str} ;; {kind_str} not directly mapped"
                ));
            }
            // AES-NI software instructions (ARM64 stubs)
            IrInstruction::AesEnc { .. } | IrInstruction::AesEncLast { .. }
            | IrInstruction::AesDec { .. } | IrInstruction::AesDecLast { .. }
            | IrInstruction::AesImc { .. } | IrInstruction::AesKeyGenAssist { .. } => {
                instructions.push("// AES-NI software (interpreter only)".to_string());
            }
            // PCLMULQDQ software instruction (ARM64 stub)
            IrInstruction::Pclmulqdq { dst, src, imm } => {
                // ARM64 JIT lowering: PMULL/PMULL2 with EXT for half selection.
                // The JIT compiler emits actual ARM64 PMULL instructions (see jit.rs).
                let use_dst_hi = (*imm & 0x01) != 0;
                let use_src_hi = (*imm & 0x10) != 0;
                let sel = match (use_dst_hi, use_src_hi) {
                    (false, false) => "low×low",
                    (true, true) => "high×high",
                    (true, false) => "high×low",
                    (false, true) => "low×high",
                };
                instructions.push(format!(
                    "// pmull v{}, v{}.1d, v{}.1d ;; pclmulqdq xmm{}, xmm{}, imm={:#x} ({})",
                    dst, dst, src, dst, src, imm, sel
                ));
            }
            // SHA software instructions (ARM64 stubs)
            IrInstruction::Sha1Rnds4 { .. } | IrInstruction::Sha1NextE { .. }
            | IrInstruction::Sha1Msg1 { .. } | IrInstruction::Sha1Msg2 { .. }
            | IrInstruction::Sha256Rnds2 { .. } | IrInstruction::Sha256Msg1 { .. }
            | IrInstruction::Sha256Msg2 { .. } => {
                instructions.push("// SHA software (interpreter only)".to_string());
            }
            // BOUND — array bounds check (32-bit mode only, interpreter fallback)
            IrInstruction::Bound { reg, address: _, width } => {
                instructions.push(format!(
                    "// bound x{}, [mem+{}]; ldr w_lower, [mem]; ldr w_upper, [mem+{}]; cmp x{}, w_lower; cmp x{}, w_upper; b.lo #br_fault",
                    reg.index(), width, width, reg.index(), reg.index()
                ));
            }
            IrInstruction::Clflush { .. } => {
                // CLFLUSH/CLFLUSHOPT is a no-op on Apple Silicon.
            }
            // === Phase H: RDPMC (performance counter) ===
            IrInstruction::Rdpmc { .. } => {
                instructions.push("// RDPMC: interpreter only (performance counter)".to_string());
            }
            // === Phase H: Cache operations ===
            IrInstruction::Clflushopt { .. } => {
                // CLFLUSHOPT is a no-op on Apple Silicon.
            }
            IrInstruction::Clwb { .. } => {
                // CLWB is a no-op on Apple Silicon.
            }
            IrInstruction::Pcommit => {
                // PCOMMIT is a no-op on Apple Silicon.
            }
            // === Phase H: TSX/RTM ===
            IrInstruction::Xbegin { .. } => {
                // XBEGIN with RTM disabled: abort with EAX=0, ZF=1
                instructions.push("// XBEGIN: RTM unavailable, abort".to_string());
                instructions.push("mov x0, #0".to_string());
                // Set ZF via flags (simplified: no direct flag access in JIT)
            }
            IrInstruction::Xend => {
                // XEND: NOP when RTM disabled
            }
            IrInstruction::Xabort { .. } => {
                // XABORT: NOP when RTM disabled
            }
            IrInstruction::Xtest => {
                // XTEST: always returns not-in-transaction
                instructions.push("// XTEST: RTM unavailable".to_string());
                instructions.push("mov x0, #0".to_string());
            }
            // === Phase H: SGX stubs ===
            // ENCLS/ENCLU: SGX is unavailable in the emulated environment.
            // The x86 behavior when SGX is not enabled is #UD (undefined instruction).
            // Since we can't deliver #UD from JIT, we set RAX to an error code
            // indicating the function is not supported, matching behavior of
            // software that probes SGX availability via these instructions.
            IrInstruction::Encls => {
                instructions.push("// ENCLS: SGX unavailable — set RAX=1 (SGX not available)".to_string());
                instructions.push("mov x0, #1".to_string());
            }
            IrInstruction::Enclu => {
                instructions.push("// ENCLU: SGX unavailable — set RAX=1 (SGX not available)".to_string());
                instructions.push("mov x0, #1".to_string());
            }
            // === Phase H: CET shadow stack (interpreter only) ===
            IrInstruction::SaveSsP { .. }
            | IrInstruction::Rstorssp { .. }
            | IrInstruction::Incssp { .. }
            | IrInstruction::Wrss { .. }
            | IrInstruction::Wruss { .. } => {
                instructions.push("// CET shadow stack: interpreter only".to_string());
            }
            // === Phase H: MPX bounds checking (interpreter only) ===
            IrInstruction::BndmkReg { .. } | IrInstruction::BndmkMem { .. }
            | IrInstruction::BndclReg { .. } | IrInstruction::BndclMem { .. }
            | IrInstruction::BndcuReg { .. } | IrInstruction::BndcuMem { .. }
            | IrInstruction::BndcnReg { .. } | IrInstruction::BndcnMem { .. }
            | IrInstruction::BndmovReg { .. } | IrInstruction::BndmovMemLoad { .. }
            | IrInstruction::BndmovMemStore { .. } => {
                instructions.push("// MPX bounds checking: interpreter only".to_string());
            }
            // === Phase H: AVX-512 operations (interpreter only) ===
            IrInstruction::AddPacked { .. } | IrInstruction::SubPacked { .. }
            | IrInstruction::MulPacked { .. } | IrInstruction::DivPacked { .. }
            | IrInstruction::MinPacked { .. } | IrInstruction::MaxPacked { .. }
            | IrInstruction::SqrtPacked { .. } | IrInstruction::ComparePacked { .. }
            | IrInstruction::ConvertPacked { .. } | IrInstruction::ConvertToInt { .. }
            | IrInstruction::ConvertFromInt { .. }
            | IrInstruction::FixupSpecial { .. } | IrInstruction::ExtractExponent { .. }
            | IrInstruction::ExtractMantissa { .. } | IrInstruction::ReducePrecision { .. }
            | IrInstruction::RangePacked { .. } | IrInstruction::ScaleByPower2 { .. }
            | IrInstruction::FloatClass { .. }
            | IrInstruction::Pternlog { .. } | IrInstruction::ConflictDetect { .. }
            | IrInstruction::CompressVector { .. } | IrInstruction::ExpandVector { .. }
            | IrInstruction::GatherVector { .. } | IrInstruction::ScatterVector { .. }
            | IrInstruction::ShuffleF32 { .. } | IrInstruction::ShuffleF64 { .. }
            | IrInstruction::AlignD { .. } | IrInstruction::AlignQ { .. }
            | IrInstruction::InsertSubVector { .. } | IrInstruction::ExtractSubVector { .. }
            | IrInstruction::BroadcastSubVector { .. } | IrInstruction::BroadcastMask { .. }
            | IrInstruction::PermuteVarDq { .. } | IrInstruction::PermuteVarPsPd { .. }
            | IrInstruction::PermuteI2 { .. } | IrInstruction::PermuteT2 { .. }
            | IrInstruction::PermuteImm { .. } | IrInstruction::PermuteImm2Src { .. }
            // === Phase H: Mask register ops (interpreter only) ===
            | IrInstruction::Kand { .. } | IrInstruction::Kor { .. }
            | IrInstruction::Kxor { .. } | IrInstruction::Knot { .. }
            | IrInstruction::Kshiftl { .. } | IrInstruction::Kshiftr { .. }
            | IrInstruction::Kadd { .. } | IrInstruction::Ktest { .. }
            | IrInstruction::Kunpck { .. } => {
                instructions.push("// AVX-512/TSX/SGX: interpreter only".to_string());
            }
            _ => {
                instructions.push("// unmapped IR instruction".to_string());
            }
        }
    }
    instructions
}
