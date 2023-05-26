use crate::opcodes;
use std::collections::HashMap;

bitflags! {
    /// # Status Register (P) http://wiki.nesdev.com/w/index.php/Status_flags
    ///
    ///  7 6 5 4 3 2 1 0
    ///  N V _ B D I Z C
    ///  | |   | | | | +--- Carry Flag
    ///  | |   | | | +----- Zero Flag
    ///  | |   | | +------- Interrupt Disable
    ///  | |   | +--------- Decimal Mode (not used on NES)
    ///  | |   +----------- Break Command
    ///  | +--------------- Overflow Flag
    ///  +----------------- Negative Flag
    ///
     pub struct CpuFlags: u8 {
        const CARRY             = 0b00000001;
        const ZERO              = 0b00000010;
        const INTERRUPT_DISABLE = 0b00000100;
        const DECIMAL_MODE      = 0b00001000;
        const BREAK             = 0b00010000;
        const BREAK2            = 0b00100000;
        const OVERFLOW          = 0b01000000;
        const NEGATIVE           = 0b10000000;
    }
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum AddressingMode {
    Immediate,
    ZeroPage,
    ZeroPage_X,
    ZeroPage_Y,
    Absolute,
    Absolute_X,
    Absolute_Y,
    Indirect,
    Indirect_X,
    Indirect_Y,
    Accumulator,
    Relative,
    Implied,
    NoneAddressing,
}

const STACK: u16 = 0x0100;
const STACK_RESET: u8 = 0xfd;

pub struct CPU {
    pub register_a: u8,
    pub register_x: u8,
    pub register_y: u8,
    pub stack_pointer: u8,
    pub status: CpuFlags,
    pub program_counter: u16,
    memory: [u8; 0xFFFF],
}

impl CPU {
    pub fn new() -> Self {
        CPU {
            register_a: 0,
            register_x: 0,
            register_y: 0,
            stack_pointer: 0,
            status: CpuFlags::from_bits_truncate(0b100100),
            program_counter: 0,
            memory: [0; 0xFFFF],
        }
    }

    fn get_operand_address(&self, mode: &AddressingMode) -> u16 {
        match mode {
            AddressingMode::Immediate => self.program_counter,

            AddressingMode::ZeroPage => self.mem_read(self.program_counter) as u16,

            AddressingMode::Absolute => self.mem_read_u16(self.program_counter),

            AddressingMode::ZeroPage_X => {
                let pos = self.mem_read(self.program_counter);
                let addr = pos.wrapping_add(self.register_x) as u16;
                addr
            }
            AddressingMode::ZeroPage_Y => {
                let pos = self.mem_read(self.program_counter);
                let addr = pos.wrapping_add(self.register_y) as u16;
                addr
            }

            AddressingMode::Absolute_X => {
                let base = self.mem_read_u16(self.program_counter);
                let addr = base.wrapping_add(self.register_x as u16);
                addr
            }
            AddressingMode::Absolute_Y => {
                let base = self.mem_read_u16(self.program_counter);
                let addr = base.wrapping_add(self.register_y as u16);
                addr
            }

            AddressingMode::Indirect_X => {
                let base = self.mem_read(self.program_counter);

                let ptr: u8 = (base as u8).wrapping_add(self.register_x);
                let lo = self.mem_read(ptr as u16);
                let hi = self.mem_read(ptr.wrapping_add(1) as u16);
                (hi as u16) << 8 | (lo as u16)
            }
            AddressingMode::Indirect_Y => {
                let base = self.mem_read(self.program_counter);

                let lo = self.mem_read(base as u16);
                let hi = self.mem_read((base as u8).wrapping_add(1) as u16);
                let deref_base = (hi as u16) << 8 | (lo as u16);
                let deref = deref_base.wrapping_add(self.register_y as u16);
                deref
            }
            AddressingMode::Implied => {
                panic!("mode {:?} is not supported", mode);
            }
            AddressingMode::Accumulator => {
                panic!("mode {:?} is not supported", mode);
            }
            AddressingMode::NoneAddressing => {
                panic!("mode {:?} is not supported", mode);
            }
            AddressingMode::Indirect => {
                panic!("mode {:?} is not supported", mode);
            }
            AddressingMode::Relative => {
                panic!("mode {:?} is not supported", mode);
            }
        }
    }

    fn adc(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(&mode);
        let data = self.mem_read(addr);

        self.add_to_register_a(data)
    }

    fn and(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(&mode);
        let data = self.mem_read(addr);

        let result = self.register_a & data;

        self.set_register_a(result);
    }

    fn asl(&mut self, mode: &AddressingMode) -> u8 {
        let addr = self.get_operand_address(&mode);
        let data = self.mem_read(addr);

        if data >> 7 == 1 {
            self.status.insert(CpuFlags::CARRY)
        } else {
            self.status.remove(CpuFlags::CARRY)
        }

        let result = data << 1;

        self.mem_write(addr, result);
        self.update_zero_and_negative_flags(result);
        result
    }

    fn asl_accumulator(&mut self, mode: &AddressingMode) -> u8 {
        let data = self.register_a;

        if data >> 7 == 1 {
            self.status.insert(CpuFlags::CARRY)
        } else {
            self.status.remove(CpuFlags::CARRY)
        }

        let result = data << 1;
        self.set_register_a(result);

        result
    }

    fn bit(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(&mode);
        let data = self.mem_read(addr);

        let and = data & self.register_a;

        if and == 0 {
            self.status.insert(CpuFlags::ZERO);
        } else {
            self.status.remove(CpuFlags::ZERO);
        }

        self.status.set(CpuFlags::NEGATIVE, 0b1000000 & data > 0);
        self.status.set(CpuFlags::OVERFLOW, 0b0100000 & data > 0);
    }

    fn branch(&mut self, condition: bool) {
        if condition {
            let jump = self.mem_read(self.program_counter);
            let jump_add = self
                .program_counter
                .wrapping_add(1)
                .wrapping_add(jump as u16);
            self.program_counter = jump_add;
        }
    }

    fn compare(&mut self, mode: &AddressingMode, compare_value: u8) {
        let addr = self.get_operand_address(&mode);
        let value = self.mem_read(addr);

        if compare_value >= value {
            self.status.insert(CpuFlags::CARRY);
        } else {
            self.status.remove(CpuFlags::CARRY);
        }
        self.update_zero_and_negative_flags(compare_value.wrapping_sub(value))
    }

    fn lda(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(&mode);
        let value = self.mem_read(addr);

        self.register_a = value;
        self.update_zero_and_negative_flags(self.register_a);
    }

    fn ldx(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(&mode);
        let value = self.mem_read(addr);

        self.register_x = value;
        self.update_zero_and_negative_flags(self.register_x);
    }

    fn ldy(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(&mode);
        let value = self.mem_read(addr);

        self.register_y = value;
        self.update_zero_and_negative_flags(self.register_y);
    }

    fn lsr(&mut self, mode: &AddressingMode) -> u8 {
        let addr = self.get_operand_address(&mode);
        let mut value = self.mem_read(addr);

        if value & 1 == 1 {
            self.status.insert(CpuFlags::CARRY);
        } else {
            self.status.remove(CpuFlags::CARRY);
        }
        value = value >> 1;
        self.mem_write(addr, value);
        self.update_zero_and_negative_flags(self.register_y);
        value
    }

    fn lsr_accumulator(&mut self) {
        let mut value = self.register_a;
        if value & 1 == 1 {
            self.status.insert(CpuFlags::CARRY);
        } else {
            self.status.remove(CpuFlags::CARRY);
        }
        value = value >> 1;
        self.set_register_a(value)
    }

    fn ora(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(&mode);
        let value = self.mem_read(addr);

        self.register_a = self.register_a | value;
        self.update_zero_and_negative_flags(self.register_a);
    }

    fn pha(&mut self, mode: &AddressingMode) {
        self.stack_pointer = self.register_a;
    }

    fn php(&mut self, mode: &AddressingMode) {
        self.stack_pointer = self.status.bits();
    }

    fn pla(&mut self, mode: &AddressingMode) {
        self.set_register_a(self.stack_pointer);
    }

    fn plp(&mut self, mode: &AddressingMode) {
        // self.set_register_a(self.stack_pointer);
        self.status
            .insert(CpuFlags::from_bits_truncate(self.stack_pointer));
    }

    fn rol(&mut self, mode: &AddressingMode) -> u8 {
        let addr = self.get_operand_address(mode);
        let mut value = self.mem_read(addr);
        let old_carry = self.status.contains(CpuFlags::CARRY);

        if value >> 7 == 1 {
            self.status.insert(CpuFlags::CARRY)
        } else {
            self.status.remove(CpuFlags::CARRY)
        }

        value = value << 1;

        if old_carry {
            value = value | 1;
        }
        self.mem_write(addr, value);
        self.update_zero_and_negative_flags(value);
        value
    }

    fn rol_accumulator(&mut self, mode: &AddressingMode) {
        let mut value = self.register_a;
        let old_carry = self.status.contains(CpuFlags::CARRY);

        if value >> 7 == 1 {
            self.status.insert(CpuFlags::CARRY)
        } else {
            self.status.remove(CpuFlags::CARRY)
        }

        value = value << 1;

        if old_carry {
            value = value | 1;
        }
        self.set_register_a(value)
    }

    fn ror_accumulator(&mut self, mode: &AddressingMode) {
        let mut value = self.register_a;
        let old_carry = self.status.contains(CpuFlags::CARRY);

        if value & 1 == 1 {
            self.status.insert(CpuFlags::CARRY)
        } else {
            self.status.remove(CpuFlags::CARRY)
        }

        value = value >> 1;

        if old_carry {
            value = value & 0b10000000;
        }
        self.set_register_a(value)
    }

    fn ror(&mut self, mode: &AddressingMode) -> u8 {
        let addr = self.get_operand_address(mode);
        let mut value = self.mem_read(addr);
        let old_carry = self.status.contains(CpuFlags::CARRY);

        if value & 1 == 1 {
            self.status.insert(CpuFlags::CARRY)
        } else {
            self.status.remove(CpuFlags::CARRY)
        }

        value = value >> 1;

        if old_carry {
            value = value & 0b10000000;
        }
        self.mem_write(addr, value);
        self.update_zero_and_negative_flags(value);
        value
    }

    fn rti(&mut self, mode: &AddressingMode) {
        self.status.bits = self.stack_pop();
        self.status.remove(CpuFlags::BREAK);
        self.status.insert(CpuFlags::BREAK2);

        self.program_counter = self.stack_pop_u16();
    }

    fn rts(&mut self, mode: &AddressingMode) {
        self.program_counter = self.stack_pop_u16() + 1;
    }

    fn sbc(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(&mode);
        let data = self.mem_read(addr);
        self.add_to_register_a(((data as i8).wrapping_neg().wrapping_sub(1)) as u8);
    }

    fn sec(&mut self, mode: &AddressingMode) {
        self.status.insert(CpuFlags::CARRY);
    }

    fn dec(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        let mut value = self.mem_read(addr);

        value = value.wrapping_sub(1);

        self.mem_write(addr, value);
        self.update_zero_and_negative_flags(value);
    }

    fn dex(&mut self) {
        self.register_x = self.register_x.wrapping_sub(1);
        self.update_zero_and_negative_flags(self.register_x);
    }

    fn dey(&mut self) {
        self.register_y = self.register_y.wrapping_sub(1);
        self.update_zero_and_negative_flags(self.register_y);
    }

    fn eor(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        let value = self.mem_read(addr);

        self.register_a = value ^ self.register_a;

        self.update_zero_and_negative_flags(self.register_a);
    }

    fn inc(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        let value: u8 = self.mem_read(addr);

        let result = value.wrapping_add(1);
        self.mem_write(addr, result);

        self.update_zero_and_negative_flags(result);
    }

    fn inx(&mut self) {
        self.register_x = self.register_x.wrapping_add(1);

        self.update_zero_and_negative_flags(self.register_x);
    }

    fn iny(&mut self) {
        self.register_y = self.register_y.wrapping_add(1);

        self.update_zero_and_negative_flags(self.register_y);
    }

    fn stack_pop(&mut self) -> u8 {
        self.stack_pointer = self.stack_pointer.wrapping_add(1);
        self.mem_read(STACK as u16 + self.stack_pointer as u16)
    }

    fn stack_pop_u16(&mut self) -> u16 {
        let lo = self.stack_pop() as u16;
        let hi = self.stack_pop() as u16;

        hi << 8 | lo
    }

    fn sta(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        self.mem_write(addr, self.register_a);
    }

    fn stx(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        self.mem_write(addr, self.register_x);
    }

    fn sty(&mut self, mode: &AddressingMode) {
        let addr = self.get_operand_address(mode);
        self.mem_write(addr, self.register_y);
    }

    fn tax(&mut self) {
        self.register_x = self.register_a;
        self.update_zero_and_negative_flags(self.register_x);
    }

    fn tay(&mut self) {
        self.register_x = self.register_y;
        self.update_zero_and_negative_flags(self.register_x);
    }

    fn tsx(&mut self) {
        self.register_x = self.stack_pointer;
        self.update_zero_and_negative_flags(self.register_x);
    }

    fn txa(&mut self) {
        self.register_a = self.register_x;
        self.update_zero_and_negative_flags(self.register_a);
    }

    fn txs(&mut self) {
        self.stack_pointer = self.register_x;
    }

    fn tya(&mut self) {
        self.register_a = self.register_y;
        self.update_zero_and_negative_flags(self.register_a);
    }

    fn stack_push(&mut self, data: u8) {
        self.mem_write((STACK as u16) + self.stack_pointer as u16, data);
        self.stack_pointer = self.stack_pointer.wrapping_sub(1)
    }

    fn stack_push_u16(&mut self, data: u16) {
        let hi = (data >> 8) as u8;
        let lo = (data & 0xff) as u8;
        self.stack_push(hi);
        self.stack_push(lo);
    }

    fn set_carry_flag(&mut self) {
        self.status.insert(CpuFlags::CARRY)
    }

    fn set_register_a(&mut self, value: u8) {
        self.register_a = value;
        self.update_zero_and_negative_flags(value)
    }

    fn add_to_register_a(&mut self, data: u8) {
        let sum = self.register_a as u16
            + data as u16
            + (if self.status.contains(CpuFlags::CARRY) {
                1
            } else {
                0
            }) as u16;

        let carry = sum > 0xFF;

        if carry {
            self.status.insert(CpuFlags::CARRY)
        } else {
            self.status.remove(CpuFlags::CARRY)
        }

        let result = sum as u8;

        if (result ^ data) & (result ^ self.register_a) & 0x80 != 0 {
            self.status.insert(CpuFlags::OVERFLOW)
        } else {
            self.status.remove(CpuFlags::OVERFLOW)
        }
        self.set_register_a(result)
    }

    fn update_zero_and_negative_flags(&mut self, result: u8) {
        if result == 0 {
            // self.status = self.status | 0b0000_0010;
            self.status.insert(CpuFlags::ZERO);
        } else {
            // self.status = self.status & 0b1111_1101;
            self.status.remove(CpuFlags::ZERO);
        }

        if result & 0b1000_0000 != 0 {
            // self.status = self.status | 0b1000_0000;
            self.status.insert(CpuFlags::NEGATIVE);
        } else {
            // self.status = self.status & 0b0111_1111;
            self.status.remove(CpuFlags::NEGATIVE);
        }
    }

    pub fn load_and_run(&mut self, program: Vec<u8>) {
        self.load(program);
        self.reset();
        self.run()
    }

    pub fn load(&mut self, program: Vec<u8>) {
        //     self.memory[0x8000..(0x8000 + program.len())].copy_from_slice(&program[..]);
        //     self.mem_write_u16(0xFFFC, 0x8000);
        self.memory[0x0600..(0x0600 + program.len())].copy_from_slice(&program[..]);
        self.mem_write_u16(0xFFFC, 0x0600);
    }

    pub fn reset(&mut self) {
        self.register_a = 0;
        self.register_x = 0;
        self.register_y = 0;
        self.status = CpuFlags::from_bits_truncate(0);

        self.program_counter = self.mem_read_u16(0xFFFC);
    }

    pub fn run_with_callback<F>(&mut self, mut callback: F)
    where
        F: FnMut(&mut CPU),
    {
        let ref opcodes: HashMap<u8, &'static opcodes::OpCode> = *opcodes::OPCODES_MAP;

        loop {
            let code = self.mem_read(self.program_counter);
            self.program_counter += 1;
            let program_counter_state = self.program_counter;

            // let opcode = opcodes
            //     .get(&code)
            //     .expect(&format!("OpCode {:x} is not recognized", code));
            let opcode = opcodes.get(&code).unwrap();

            match code {
                // ADC
                0x69 | 0x65 | 0x75 | 0x6D | 0x7D | 0x79 | 0x61 | 0x71 => {
                    self.adc(&opcode.mode);
                }
                // AND
                0x29 | 0x25 | 0x35 | 0x2D | 0x3D | 0x39 | 0x21 | 0x32 => {
                    self.and(&opcode.mode);
                }
                // ASL accumulator
                0x0A => {
                    self.asl_accumulator(&opcode.mode);
                }
                // ASL
                0x06 | 0x16 | 0x0E | 0x1E => {
                    self.asl(&opcode.mode);
                }
                // BCC
                0x90 => {
                    self.branch(!self.status.contains(CpuFlags::CARRY));
                }
                // BCS
                0xB0 => {
                    self.branch(self.status.contains(CpuFlags::CARRY));
                }
                // BEQ
                0xF0 => {
                    self.branch(self.status.contains(CpuFlags::ZERO));
                }
                // BIT
                0x24 | 0x2C => {
                    self.bit(&opcode.mode);
                }
                // BMI
                0x30 => {
                    self.branch(self.status.contains(CpuFlags::NEGATIVE));
                }
                //BNE
                0xD0 => {
                    self.branch(!self.status.contains(CpuFlags::ZERO));
                }
                // BPL
                0x10 => {
                    self.branch(!self.status.contains(CpuFlags::NEGATIVE));
                }

                // BVC
                0x50 => {
                    self.branch(!self.status.contains(CpuFlags::OVERFLOW));
                }

                // BVS
                0x70 => {
                    self.branch(self.status.contains(CpuFlags::OVERFLOW));
                }

                // CLC
                0x18 => self.status.remove(CpuFlags::CARRY),

                // CLD
                0xD8 => self.status.remove(CpuFlags::DECIMAL_MODE),

                // CLI
                0x58 => self.status.remove(CpuFlags::INTERRUPT_DISABLE),

                // CMP
                0xC9 | 0xC5 | 0xD5 | 0xCD | 0xDD | 0xD9 | 0xC1 | 0xD1 => {
                    self.compare(&opcode.mode, self.register_a);
                }

                // CPX
                0xE0 | 0xE4 | 0xEC => {
                    self.compare(&opcode.mode, self.register_x);
                }

                // CPY
                0xC0 | 0xC4 | 0xCC => {
                    self.compare(&opcode.mode, self.register_y);
                }

                // DEC
                0xC6 | 0xD6 | 0xCE | 0xDE => {
                    self.dec(&opcode.mode);
                }

                // DEX
                0xCA => self.dex(),

                // DEY
                0x88 => self.dey(),

                // EOR
                0x49 | 0x45 | 0x55 | 0x4D | 0x5D | 0x59 | 0x41 | 0x51 => self.eor(&opcode.mode),

                // INC
                0xE6 | 0xF6 | 0xEE | 0xFE => self.inc(&opcode.mode),

                // INX
                0xE8 => self.inx(),

                // INY
                0xC8 => self.iny(),

                /* JMP Absolute */
                0x4C => {
                    let mem_address = self.mem_read_u16(self.program_counter);
                    self.program_counter = mem_address;
                }

                /* JMP Indirect */
                0x6C => {
                    let mem_address = self.mem_read_u16(self.program_counter);
                    // let indirect_ref = self.mem_read_u16(mem_address);
                    //6502 bug mode with with page boundary:
                    //  if address $3000 contains $40, $30FF contains $80, and $3100 contains $50,
                    // the result of JMP ($30FF) will be a transfer of control to $4080 rather than $5080 as you intended
                    // i.e. the 6502 took the low byte of the address from $30FF and the high byte from $3000

                    let indirect_ref = if mem_address & 0x00FF == 0x00FF {
                        let lo = self.mem_read(mem_address);
                        let hi = self.mem_read(mem_address & 0xFF00);
                        (hi as u16) << 8 | (lo as u16)
                    } else {
                        self.mem_read_u16(mem_address)
                    };

                    self.program_counter = indirect_ref;
                }

                /* JSR */
                0x20 => {
                    self.stack_push_u16(self.program_counter + 2 - 1);
                    let target_address = self.mem_read_u16(self.program_counter);
                    self.program_counter = target_address
                }

                // LDA
                0xa9 | 0xa5 | 0xb5 | 0xad | 0xbd | 0xb9 | 0xa1 | 0xb1 => {
                    self.lda(&opcode.mode);
                }

                // LDX
                0xA2 | 0xA6 | 0xB6 | 0xAE | 0xBE => {
                    self.ldx(&opcode.mode);
                }

                // LDY
                0xA0 | 0xA4 | 0xB4 | 0xAC | 0xBC => {
                    self.ldy(&opcode.mode);
                }

                // LSR_ACCUMULATOR
                0x4A => self.lsr_accumulator(),

                // LSR
                0x46 | 0x56 | 0x4E | 0x5E => {
                    self.lsr(&opcode.mode);
                }

                // NOP
                0xEA => {
                    // NOTHING TO DO
                }

                // ORA
                0x09 | 0x05 | 0x15 | 0x0D | 0x1d | 0x19 | 0x01 | 0x11 => {
                    self.ora(&opcode.mode);
                }

                // PHA
                0x48 => {
                    self.pha(&opcode.mode);
                }

                // PHP
                0x08 => {
                    self.php(&opcode.mode);
                }

                // PLA
                0x68 => {
                    self.pla(&opcode.mode);
                }

                // PLP
                0x28 => {
                    self.plp(&opcode.mode);
                }

                // ROL_ACCUMULATOR
                0x2A => {
                    self.rol_accumulator(&opcode.mode);
                }
                // ROL
                0x26 | 0x36 | 0x2E | 0x3E => {
                    self.rol(&opcode.mode);
                }

                // ROR_ACCUMULATOR
                0x6A => {
                    self.rol_accumulator(&opcode.mode);
                }
                // ROR
                0x66 | 0x76 | 0x6E | 0x7E => {
                    self.rol(&opcode.mode);
                }

                // RTI
                0x40 => {
                    self.rti(&opcode.mode);
                }

                // RTS
                0x60 => {
                    self.rts(&opcode.mode);
                }

                // SBC
                0xE9 | 0xE5 | 0xF5 | 0xED | 0xFD | 0xF9 | 0xE1 | 0xF1 => {
                    self.sbc(&opcode.mode);
                }

                // SEC
                0x38 => {
                    self.set_carry_flag();
                }

                // SED
                0xF8 => {
                    self.status.insert(CpuFlags::DECIMAL_MODE);
                }

                // SEI
                0x78 => {
                    self.status.insert(CpuFlags::INTERRUPT_DISABLE);
                }

                // STA
                0x85 | 0x95 | 0x8D | 0x9D | 0x99 | 0x81 | 0x91 => {
                    self.sta(&opcode.mode);
                }

                // STX
                0x86 | 0x96 | 0x8E => {
                    self.stx(&opcode.mode);
                }

                // STY
                0x84 | 0x94 | 0x8C => {
                    self.sty(&opcode.mode);
                }

                // TAX
                0xAA => self.tax(),

                // TAY
                0xA8 => self.tay(),

                // TSX
                0xBA => self.tsx(),

                // TXA
                0x8A => self.txa(),

                // TXS
                0x9A => self.txs(),

                // TYA
                0x98 => self.tya(),
                // 0xE8 => self.inx(),

                // BRK
                0x00 => return,
                _ => {
                    println!("code not implement")
                    // panic!()
                }
            }

            if program_counter_state == self.program_counter {
                self.program_counter += (opcode.len - 1) as u16;
            }

            callback(self);
            // ..
        }
    }

    pub fn run(&mut self) {
        self.run_with_callback(|_| {});

        // let ref opcodes: HashMap<u8, &'static opcodes::OpCode> = *opcodes::OPCODES_MAP;

        // loop {}
    }
}

impl Mem for CPU {
    fn mem_read(&self, addr: u16) -> u8 {
        self.memory[addr as usize]
    }

    fn mem_write(&mut self, addr: u16, data: u8) {
        self.memory[addr as usize] = data;
    }
}

pub trait Mem {
    fn mem_read(&self, addr: u16) -> u8;

    fn mem_write(&mut self, addr: u16, data: u8);

    fn mem_read_u16(&self, pos: u16) -> u16 {
        let lo = self.mem_read(pos) as u16;
        let hi = self.mem_read(pos + 1) as u16;
        (hi << 8) | (lo as u16)
    }

    fn mem_write_u16(&mut self, pos: u16, data: u16) {
        let hi = (data >> 8) as u8;
        let lo = (data & 0xff) as u8;
        self.mem_write(pos, lo);
        self.mem_write(pos + 1, hi);
    }
}
