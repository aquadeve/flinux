/*
 * This file is part of Foreign Linux.
 *
 * Copyright (C) 2014, 2015 Xiangyan Sun <wishstudio@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * x86 Interpreter
 *
 * Software interpreter for IA-32 instructions. Decodes and executes
 * x86 instructions one at a time on the virtual CPU, translating
 * memory accesses through the guest address space.
 */

#include <dbt/x86_interp.h>
#include <dbt/x86_decoder.h>
#include <dbt/x86_cpu.h>
#include <log.h>

#include <string.h>
#include <stdbool.h>

/* ===== EFLAGS helpers ===== */

/* Parity lookup table for low 8 bits */
static const uint8_t parity_table[256] = {
	1,0,0,1,0,1,1,0,0,1,1,0,1,0,0,1,0,1,1,0,1,0,0,1,1,0,0,1,0,1,1,0,
	0,1,1,0,1,0,0,1,1,0,0,1,0,1,1,0,1,0,0,1,0,1,1,0,0,1,1,0,1,0,0,1,
	0,1,1,0,1,0,0,1,1,0,0,1,0,1,1,0,1,0,0,1,0,1,1,0,0,1,1,0,1,0,0,1,
	1,0,0,1,0,1,1,0,0,1,1,0,1,0,0,1,0,1,1,0,1,0,0,1,1,0,0,1,0,1,1,0,
	0,1,1,0,1,0,0,1,1,0,0,1,0,1,1,0,1,0,0,1,0,1,1,0,0,1,1,0,1,0,0,1,
	1,0,0,1,0,1,1,0,0,1,1,0,1,0,0,1,0,1,1,0,1,0,0,1,1,0,0,1,0,1,1,0,
	1,0,0,1,0,1,1,0,0,1,1,0,1,0,0,1,0,1,1,0,1,0,0,1,1,0,0,1,0,1,1,0,
	0,1,1,0,1,0,0,1,1,0,0,1,0,1,1,0,1,0,0,1,0,1,1,0,0,1,1,0,1,0,0,1,
};

static inline uint32_t update_flags_add(uint32_t eflags, uint32_t a, uint32_t b, uint32_t result, int bits)
{
	uint32_t mask = (bits == 8) ? 0xFF : (bits == 16) ? 0xFFFF : 0xFFFFFFFF;
	uint32_t sign = (bits == 8) ? 0x80 : (bits == 16) ? 0x8000 : 0x80000000;
	uint32_t r = result & mask;

	eflags &= ~(X86_CF | X86_PF | X86_AF | X86_ZF | X86_SF | X86_OF);

	if (r == 0) eflags |= X86_ZF;
	if (r & sign) eflags |= X86_SF;
	if (parity_table[r & 0xFF]) eflags |= X86_PF;
	if ((a ^ b ^ result) & 0x10) eflags |= X86_AF;

	/* CF: carry out of MSB */
	if ((uint64_t)(a & mask) + (uint64_t)(b & mask) > mask)
		eflags |= X86_CF;

	/* OF: signed overflow */
	if (((a ^ result) & (b ^ result)) & sign)
		eflags |= X86_OF;

	return eflags;
}

static inline uint32_t update_flags_sub(uint32_t eflags, uint32_t a, uint32_t b, uint32_t result, int bits)
{
	uint32_t mask = (bits == 8) ? 0xFF : (bits == 16) ? 0xFFFF : 0xFFFFFFFF;
	uint32_t sign = (bits == 8) ? 0x80 : (bits == 16) ? 0x8000 : 0x80000000;
	uint32_t r = result & mask;

	eflags &= ~(X86_CF | X86_PF | X86_AF | X86_ZF | X86_SF | X86_OF);

	if (r == 0) eflags |= X86_ZF;
	if (r & sign) eflags |= X86_SF;
	if (parity_table[r & 0xFF]) eflags |= X86_PF;
	if ((a ^ b ^ result) & 0x10) eflags |= X86_AF;

	/* CF: borrow */
	if ((a & mask) < (b & mask))
		eflags |= X86_CF;

	/* OF: signed overflow */
	if (((a ^ b) & (a ^ result)) & sign)
		eflags |= X86_OF;

	return eflags;
}

static inline uint32_t update_flags_logic(uint32_t eflags, uint32_t result, int bits)
{
	uint32_t mask = (bits == 8) ? 0xFF : (bits == 16) ? 0xFFFF : 0xFFFFFFFF;
	uint32_t sign = (bits == 8) ? 0x80 : (bits == 16) ? 0x8000 : 0x80000000;
	uint32_t r = result & mask;

	eflags &= ~(X86_CF | X86_PF | X86_AF | X86_ZF | X86_SF | X86_OF);

	if (r == 0) eflags |= X86_ZF;
	if (r & sign) eflags |= X86_SF;
	if (parity_table[r & 0xFF]) eflags |= X86_PF;
	/* CF and OF are cleared by logic ops */

	return eflags;
}

static inline int opsz_bits(enum x86_op_size sz)
{
	switch (sz)
	{
	case OPSZ_8: return 8;
	case OPSZ_16: return 16;
	case OPSZ_32: return 32;
	}
	return 32;
}

static inline uint32_t opsz_mask(enum x86_op_size sz)
{
	switch (sz)
	{
	case OPSZ_8: return 0xFF;
	case OPSZ_16: return 0xFFFF;
	case OPSZ_32: return 0xFFFFFFFF;
	}
	return 0xFFFFFFFF;
}

/* ===== Condition code evaluation ===== */

static inline bool eval_cc(uint32_t eflags, enum x86_cc cc)
{
	switch (cc)
	{
	case CC_O:   return (eflags & X86_OF) != 0;
	case CC_NO:  return (eflags & X86_OF) == 0;
	case CC_B:   return (eflags & X86_CF) != 0;
	case CC_NB:  return (eflags & X86_CF) == 0;
	case CC_Z:   return (eflags & X86_ZF) != 0;
	case CC_NZ:  return (eflags & X86_ZF) == 0;
	case CC_BE:  return (eflags & (X86_CF | X86_ZF)) != 0;
	case CC_NBE: return (eflags & (X86_CF | X86_ZF)) == 0;
	case CC_S:   return (eflags & X86_SF) != 0;
	case CC_NS:  return (eflags & X86_SF) == 0;
	case CC_P:   return (eflags & X86_PF) != 0;
	case CC_NP:  return (eflags & X86_PF) == 0;
	case CC_L:   return ((eflags & X86_SF) != 0) != ((eflags & X86_OF) != 0);
	case CC_NL:  return ((eflags & X86_SF) != 0) == ((eflags & X86_OF) != 0);
	case CC_LE:  return ((eflags & X86_ZF) != 0) || (((eflags & X86_SF) != 0) != ((eflags & X86_OF) != 0));
	case CC_NLE: return ((eflags & X86_ZF) == 0) && (((eflags & X86_SF) != 0) == ((eflags & X86_OF) != 0));
	}
	return false;
}

/* ===== Operand read/write helpers ===== */

/* Read 8-bit register (AL, CL, DL, BL, AH, CH, DH, BH) */
static inline uint8_t read_reg8(struct x86_cpu *cpu, uint8_t reg)
{
	if (reg < 4)
		return (uint8_t)(cpu->regs[reg] & 0xFF);
	else
		return (uint8_t)((cpu->regs[reg - 4] >> 8) & 0xFF);
}

static inline void write_reg8(struct x86_cpu *cpu, uint8_t reg, uint8_t val)
{
	if (reg < 4)
		cpu->regs[reg] = (cpu->regs[reg] & 0xFFFFFF00) | val;
	else
		cpu->regs[reg - 4] = (cpu->regs[reg - 4] & 0xFFFF00FF) | ((uint32_t)val << 8);
}

static inline uint16_t read_reg16(struct x86_cpu *cpu, uint8_t reg)
{
	return (uint16_t)(cpu->regs[reg] & 0xFFFF);
}

static inline void write_reg16(struct x86_cpu *cpu, uint8_t reg, uint16_t val)
{
	cpu->regs[reg] = (cpu->regs[reg] & 0xFFFF0000) | val;
}

/* Calculate effective address from a memory operand */
static uint32_t calc_ea(struct x86_cpu *cpu, const struct x86_mem_op *mem)
{
	uint32_t addr = 0;
	if (mem->base_reg >= 0)
		addr += cpu->regs[mem->base_reg];
	if (mem->index_reg >= 0)
		addr += cpu->regs[mem->index_reg] * mem->scale;
	addr += mem->disp;

	/* Segment override for FS/GS (TLS) */
	if (mem->seg != 0xFF)
	{
		if (mem->seg == X86_SEG_FS || mem->seg == X86_SEG_GS)
			addr += cpu->seg_base[mem->seg];
	}
	else
	{
		/* Default segment based on base register */
		/* ESP/EBP default to SS, others to DS - for simplicity, treat all flat */
	}

	/* Apply segment prefix from instruction prefixes */
	return addr;
}

static uint32_t apply_seg_prefix(struct x86_cpu *cpu, uint32_t prefixes, uint32_t addr)
{
	if (prefixes & PREFIX_SEG_FS)
		addr += cpu->seg_base[X86_SEG_FS];
	else if (prefixes & PREFIX_SEG_GS)
		addr += cpu->seg_base[X86_SEG_GS];
	return addr;
}

/* Read an operand value */
static uint32_t read_operand(struct x86_cpu *cpu, const struct x86_operand *op, uint32_t prefixes)
{
	switch (op->type)
	{
	case OP_REG:
		switch (op->size)
		{
		case OPSZ_8:  return read_reg8(cpu, op->reg);
		case OPSZ_16: return read_reg16(cpu, op->reg);
		case OPSZ_32: return cpu->regs[op->reg];
		}
		break;
	case OP_MEM:
	{
		uint32_t ea = calc_ea(cpu, &op->mem);
		if (op->mem.seg == 0xFF)
			ea = apply_seg_prefix(cpu, prefixes, ea);
		switch (op->size)
		{
		case OPSZ_8:  return x86_cpu_read8(cpu, ea);
		case OPSZ_16: return x86_cpu_read16(cpu, ea);
		case OPSZ_32: return x86_cpu_read32(cpu, ea);
		}
		break;
	}
	case OP_IMM:
		return op->imm;
	default:
		break;
	}
	return 0;
}

/* Write an operand value */
static void write_operand(struct x86_cpu *cpu, const struct x86_operand *op, uint32_t val, uint32_t prefixes)
{
	switch (op->type)
	{
	case OP_REG:
		switch (op->size)
		{
		case OPSZ_8:  write_reg8(cpu, op->reg, (uint8_t)val); break;
		case OPSZ_16: write_reg16(cpu, op->reg, (uint16_t)val); break;
		case OPSZ_32: cpu->regs[op->reg] = val; break;
		}
		break;
	case OP_MEM:
	{
		uint32_t ea = calc_ea(cpu, &op->mem);
		if (op->mem.seg == 0xFF)
			ea = apply_seg_prefix(cpu, prefixes, ea);
		switch (op->size)
		{
		case OPSZ_8:  x86_cpu_write8(cpu, ea, (uint8_t)val); break;
		case OPSZ_16: x86_cpu_write16(cpu, ea, (uint16_t)val); break;
		case OPSZ_32: x86_cpu_write32(cpu, ea, val); break;
		}
		break;
	}
	default:
		break;
	}
}

/* Get effective address of a memory operand (for LEA, etc.) */
static uint32_t get_ea(struct x86_cpu *cpu, const struct x86_operand *op)
{
	if (op->type == OP_MEM)
		return calc_ea(cpu, &op->mem);
	return 0;
}

/* ===== Instruction execution ===== */

static enum x86_exit_reason exec_insn(struct x86_cpu *cpu, struct x86_insn *insn)
{
	uint32_t a, b, result;
	uint64_t result64;
	int bits = opsz_bits(insn->op[0].size);
	uint32_t mask = opsz_mask(insn->op[0].size);
	uint32_t pf = insn->prefixes;

	/* Advance EIP past this instruction before execution */
	uint32_t next_eip = cpu->eip + insn->length;

	switch (insn->type)
	{
	/* --- Arithmetic --- */
	case INSN_ADD:
		a = read_operand(cpu, &insn->op[0], pf);
		b = read_operand(cpu, &insn->op[1], pf);
		result = a + b;
		write_operand(cpu, &insn->op[0], result, pf);
		cpu->eflags = update_flags_add(cpu->eflags, a, b, result, bits);
		break;

	case INSN_ADC:
		a = read_operand(cpu, &insn->op[0], pf);
		b = read_operand(cpu, &insn->op[1], pf);
		result = a + b + ((cpu->eflags & X86_CF) ? 1 : 0);
		write_operand(cpu, &insn->op[0], result, pf);
		cpu->eflags = update_flags_add(cpu->eflags, a, b + ((cpu->eflags & X86_CF) ? 1 : 0), result, bits);
		break;

	case INSN_SUB:
		a = read_operand(cpu, &insn->op[0], pf);
		b = read_operand(cpu, &insn->op[1], pf);
		result = a - b;
		write_operand(cpu, &insn->op[0], result, pf);
		cpu->eflags = update_flags_sub(cpu->eflags, a, b, result, bits);
		break;

	case INSN_SBB:
		a = read_operand(cpu, &insn->op[0], pf);
		b = read_operand(cpu, &insn->op[1], pf);
		result = a - b - ((cpu->eflags & X86_CF) ? 1 : 0);
		write_operand(cpu, &insn->op[0], result, pf);
		cpu->eflags = update_flags_sub(cpu->eflags, a, b + ((cpu->eflags & X86_CF) ? 1 : 0), result, bits);
		break;

	case INSN_CMP:
		a = read_operand(cpu, &insn->op[0], pf);
		b = read_operand(cpu, &insn->op[1], pf);
		result = a - b;
		cpu->eflags = update_flags_sub(cpu->eflags, a, b, result, bits);
		break;

	case INSN_AND:
		a = read_operand(cpu, &insn->op[0], pf);
		b = read_operand(cpu, &insn->op[1], pf);
		result = a & b;
		write_operand(cpu, &insn->op[0], result, pf);
		cpu->eflags = update_flags_logic(cpu->eflags, result, bits);
		break;

	case INSN_OR:
		a = read_operand(cpu, &insn->op[0], pf);
		b = read_operand(cpu, &insn->op[1], pf);
		result = a | b;
		write_operand(cpu, &insn->op[0], result, pf);
		cpu->eflags = update_flags_logic(cpu->eflags, result, bits);
		break;

	case INSN_XOR:
		a = read_operand(cpu, &insn->op[0], pf);
		b = read_operand(cpu, &insn->op[1], pf);
		result = a ^ b;
		write_operand(cpu, &insn->op[0], result, pf);
		cpu->eflags = update_flags_logic(cpu->eflags, result, bits);
		break;

	case INSN_TEST:
		a = read_operand(cpu, &insn->op[0], pf);
		b = read_operand(cpu, &insn->op[1], pf);
		result = a & b;
		cpu->eflags = update_flags_logic(cpu->eflags, result, bits);
		break;

	case INSN_INC:
		a = read_operand(cpu, &insn->op[0], pf);
		result = a + 1;
		write_operand(cpu, &insn->op[0], result, pf);
		/* INC preserves CF */
		{
			uint32_t saved_cf = cpu->eflags & X86_CF;
			cpu->eflags = update_flags_add(cpu->eflags, a, 1, result, bits);
			cpu->eflags = (cpu->eflags & ~X86_CF) | saved_cf;
		}
		break;

	case INSN_DEC:
		a = read_operand(cpu, &insn->op[0], pf);
		result = a - 1;
		write_operand(cpu, &insn->op[0], result, pf);
		{
			uint32_t saved_cf = cpu->eflags & X86_CF;
			cpu->eflags = update_flags_sub(cpu->eflags, a, 1, result, bits);
			cpu->eflags = (cpu->eflags & ~X86_CF) | saved_cf;
		}
		break;

	case INSN_NEG:
		a = read_operand(cpu, &insn->op[0], pf);
		result = (uint32_t)(-(int32_t)a);
		write_operand(cpu, &insn->op[0], result, pf);
		cpu->eflags = update_flags_sub(cpu->eflags, 0, a, result, bits);
		break;

	case INSN_NOT:
		a = read_operand(cpu, &insn->op[0], pf);
		write_operand(cpu, &insn->op[0], ~a, pf);
		break;

	case INSN_MUL:
		a = read_operand(cpu, &insn->op[0], pf);
		if (bits == 8) {
			result = (uint32_t)(uint8_t)cpu->regs[X86_REG_EAX] * (uint32_t)(uint8_t)a;
			cpu->regs[X86_REG_EAX] = (cpu->regs[X86_REG_EAX] & 0xFFFF0000) | (result & 0xFFFF);
			cpu->eflags = (result & 0xFF00) ? (cpu->eflags | X86_CF | X86_OF) : (cpu->eflags & ~(X86_CF | X86_OF));
		} else if (bits == 16) {
			result = (uint32_t)read_reg16(cpu, X86_REG_EAX) * (uint32_t)(uint16_t)a;
			write_reg16(cpu, X86_REG_EAX, (uint16_t)result);
			write_reg16(cpu, X86_REG_EDX, (uint16_t)(result >> 16));
			cpu->eflags = (result >> 16) ? (cpu->eflags | X86_CF | X86_OF) : (cpu->eflags & ~(X86_CF | X86_OF));
		} else {
			result64 = (uint64_t)cpu->regs[X86_REG_EAX] * (uint64_t)a;
			cpu->regs[X86_REG_EAX] = (uint32_t)result64;
			cpu->regs[X86_REG_EDX] = (uint32_t)(result64 >> 32);
			cpu->eflags = (result64 >> 32) ? (cpu->eflags | X86_CF | X86_OF) : (cpu->eflags & ~(X86_CF | X86_OF));
		}
		break;

	case INSN_IMUL:
		a = read_operand(cpu, &insn->op[0], pf);
		if (bits == 8) {
			int16_t r = (int8_t)(cpu->regs[X86_REG_EAX] & 0xFF) * (int8_t)a;
			cpu->regs[X86_REG_EAX] = (cpu->regs[X86_REG_EAX] & 0xFFFF0000) | ((uint16_t)r);
		} else if (bits == 16) {
			int32_t r = (int16_t)read_reg16(cpu, X86_REG_EAX) * (int16_t)a;
			write_reg16(cpu, X86_REG_EAX, (uint16_t)r);
			write_reg16(cpu, X86_REG_EDX, (uint16_t)(r >> 16));
		} else {
			int64_t r = (int64_t)(int32_t)cpu->regs[X86_REG_EAX] * (int64_t)(int32_t)a;
			cpu->regs[X86_REG_EAX] = (uint32_t)r;
			cpu->regs[X86_REG_EDX] = (uint32_t)((uint64_t)r >> 32);
		}
		break;

	case INSN_IMUL2:
		a = read_operand(cpu, &insn->op[0], pf);
		b = read_operand(cpu, &insn->op[1], pf);
		if (bits == 16) {
			int32_t r = (int16_t)a * (int16_t)b;
			write_operand(cpu, &insn->op[0], (uint16_t)r, pf);
		} else {
			int64_t r = (int64_t)(int32_t)a * (int64_t)(int32_t)b;
			write_operand(cpu, &insn->op[0], (uint32_t)r, pf);
		}
		break;

	case INSN_IMUL3:
		b = read_operand(cpu, &insn->op[1], pf);
		{
			uint32_t imm = insn->op[2].imm;
			if (insn->op[2].size == OPSZ_8)
				imm = (uint32_t)(int32_t)(int8_t)imm;
			if (bits == 16) {
				int32_t r = (int16_t)b * (int16_t)imm;
				write_operand(cpu, &insn->op[0], (uint16_t)r, pf);
			} else {
				int64_t r = (int64_t)(int32_t)b * (int64_t)(int32_t)imm;
				write_operand(cpu, &insn->op[0], (uint32_t)r, pf);
			}
		}
		break;

	case INSN_DIV:
		a = read_operand(cpu, &insn->op[0], pf);
		if (a == 0) { cpu->eip = next_eip; return X86_EXIT_DIVZERO; }
		if (bits == 8) {
			uint16_t dividend = cpu->regs[X86_REG_EAX] & 0xFFFF;
			cpu->regs[X86_REG_EAX] = (cpu->regs[X86_REG_EAX] & 0xFFFF0000) |
				((dividend / a) & 0xFF) | (((dividend % a) & 0xFF) << 8);
		} else if (bits == 16) {
			uint32_t dividend = ((uint32_t)read_reg16(cpu, X86_REG_EDX) << 16) | read_reg16(cpu, X86_REG_EAX);
			write_reg16(cpu, X86_REG_EAX, (uint16_t)(dividend / (uint16_t)a));
			write_reg16(cpu, X86_REG_EDX, (uint16_t)(dividend % (uint16_t)a));
		} else {
			uint64_t dividend = ((uint64_t)cpu->regs[X86_REG_EDX] << 32) | cpu->regs[X86_REG_EAX];
			cpu->regs[X86_REG_EAX] = (uint32_t)(dividend / a);
			cpu->regs[X86_REG_EDX] = (uint32_t)(dividend % a);
		}
		break;

	case INSN_IDIV:
		a = read_operand(cpu, &insn->op[0], pf);
		if (a == 0) { cpu->eip = next_eip; return X86_EXIT_DIVZERO; }
		if (bits == 8) {
			int16_t dividend = (int16_t)(cpu->regs[X86_REG_EAX] & 0xFFFF);
			int8_t divisor = (int8_t)a;
			cpu->regs[X86_REG_EAX] = (cpu->regs[X86_REG_EAX] & 0xFFFF0000) |
				((uint8_t)(dividend / divisor)) | ((uint16_t)(uint8_t)(dividend % divisor) << 8);
		} else if (bits == 16) {
			int32_t dividend = (int32_t)(((uint32_t)read_reg16(cpu, X86_REG_EDX) << 16) | read_reg16(cpu, X86_REG_EAX));
			int16_t divisor = (int16_t)a;
			write_reg16(cpu, X86_REG_EAX, (uint16_t)(dividend / divisor));
			write_reg16(cpu, X86_REG_EDX, (uint16_t)(dividend % divisor));
		} else {
			int64_t dividend = (int64_t)(((uint64_t)cpu->regs[X86_REG_EDX] << 32) | cpu->regs[X86_REG_EAX]);
			int32_t divisor = (int32_t)a;
			cpu->regs[X86_REG_EAX] = (uint32_t)(int32_t)(dividend / divisor);
			cpu->regs[X86_REG_EDX] = (uint32_t)(int32_t)(dividend % divisor);
		}
		break;

	/* --- Shifts --- */
	case INSN_SHL:
		a = read_operand(cpu, &insn->op[0], pf);
		b = read_operand(cpu, &insn->op[1], pf) & 0x1F;
		if (b) {
			result = a << b;
			write_operand(cpu, &insn->op[0], result, pf);
			cpu->eflags = update_flags_logic(cpu->eflags, result, bits);
			if ((a >> (bits - b)) & 1) cpu->eflags |= X86_CF;
		}
		break;

	case INSN_SHR:
		a = read_operand(cpu, &insn->op[0], pf);
		b = read_operand(cpu, &insn->op[1], pf) & 0x1F;
		if (b) {
			result = (a & mask) >> b;
			write_operand(cpu, &insn->op[0], result, pf);
			cpu->eflags = update_flags_logic(cpu->eflags, result, bits);
			if ((a >> (b - 1)) & 1) cpu->eflags |= X86_CF;
		}
		break;

	case INSN_SAR:
		a = read_operand(cpu, &insn->op[0], pf);
		b = read_operand(cpu, &insn->op[1], pf) & 0x1F;
		if (b) {
			int32_t sa = (int32_t)(a << (32 - bits)) >> (32 - bits); /* sign-extend */
			result = (uint32_t)(sa >> b);
			write_operand(cpu, &insn->op[0], result, pf);
			cpu->eflags = update_flags_logic(cpu->eflags, result, bits);
			if ((sa >> (b - 1)) & 1) cpu->eflags |= X86_CF;
		}
		break;

	case INSN_ROL:
		a = read_operand(cpu, &insn->op[0], pf);
		b = read_operand(cpu, &insn->op[1], pf) & 0x1F;
		if (b) {
			b %= bits;
			result = (a << b) | ((a & mask) >> (bits - b));
			write_operand(cpu, &insn->op[0], result, pf);
			if (result & 1) cpu->eflags |= X86_CF; else cpu->eflags &= ~X86_CF;
		}
		break;

	case INSN_ROR:
		a = read_operand(cpu, &insn->op[0], pf);
		b = read_operand(cpu, &insn->op[1], pf) & 0x1F;
		if (b) {
			b %= bits;
			result = ((a & mask) >> b) | (a << (bits - b));
			write_operand(cpu, &insn->op[0], result, pf);
			uint32_t sign_bit = (bits == 8) ? 0x80 : (bits == 16) ? 0x8000 : 0x80000000;
			if (result & sign_bit) cpu->eflags |= X86_CF; else cpu->eflags &= ~X86_CF;
		}
		break;

	/* --- Data transfer --- */
	case INSN_MOV:
		result = read_operand(cpu, &insn->op[1], pf);
		write_operand(cpu, &insn->op[0], result, pf);
		break;

	case INSN_MOVZX:
		result = read_operand(cpu, &insn->op[1], pf);
		write_operand(cpu, &insn->op[0], result, pf);
		break;

	case INSN_MOVSX:
		a = read_operand(cpu, &insn->op[1], pf);
		if (insn->op[1].size == OPSZ_8)
			result = (uint32_t)(int32_t)(int8_t)a;
		else
			result = (uint32_t)(int32_t)(int16_t)a;
		write_operand(cpu, &insn->op[0], result, pf);
		break;

	case INSN_XCHG:
		a = read_operand(cpu, &insn->op[0], pf);
		b = read_operand(cpu, &insn->op[1], pf);
		write_operand(cpu, &insn->op[0], b, pf);
		write_operand(cpu, &insn->op[1], a, pf);
		break;

	case INSN_LEA:
		result = get_ea(cpu, &insn->op[1]);
		write_operand(cpu, &insn->op[0], result, pf);
		break;

	case INSN_CBW:
		if (insn->op_size == OPSZ_16) /* CBW: AL -> AX */
			write_reg16(cpu, X86_REG_EAX, (uint16_t)(int16_t)(int8_t)(cpu->regs[X86_REG_EAX] & 0xFF));
		else /* CWDE: AX -> EAX */
			cpu->regs[X86_REG_EAX] = (uint32_t)(int32_t)(int16_t)read_reg16(cpu, X86_REG_EAX);
		break;

	case INSN_CDQ:
		if (insn->op_size == OPSZ_16) /* CWD: AX -> DX:AX */
			write_reg16(cpu, X86_REG_EDX, ((int16_t)read_reg16(cpu, X86_REG_EAX) < 0) ? 0xFFFF : 0);
		else /* CDQ: EAX -> EDX:EAX */
			cpu->regs[X86_REG_EDX] = ((int32_t)cpu->regs[X86_REG_EAX] < 0) ? 0xFFFFFFFF : 0;
		break;

	case INSN_BSWAP:
		a = cpu->regs[insn->op[0].reg];
		cpu->regs[insn->op[0].reg] = ((a >> 24) & 0xFF) | ((a >> 8) & 0xFF00) |
			((a << 8) & 0xFF0000) | ((a << 24) & 0xFF000000);
		break;

	case INSN_CMOVcc:
		if (eval_cc(cpu->eflags, insn->cc))
		{
			result = read_operand(cpu, &insn->op[1], pf);
			write_operand(cpu, &insn->op[0], result, pf);
		}
		break;

	/* --- Stack --- */
	case INSN_PUSH:
		a = read_operand(cpu, &insn->op[0], pf);
		if (insn->op[0].size == OPSZ_8)
			a = (uint32_t)(int32_t)(int8_t)a; /* Sign-extend push imm8 */
		x86_cpu_push32(cpu, a);
		break;

	case INSN_POP:
		a = x86_cpu_pop32(cpu);
		write_operand(cpu, &insn->op[0], a, pf);
		break;

	case INSN_PUSHA:
	{
		uint32_t tmp_esp = cpu->regs[X86_REG_ESP];
		x86_cpu_push32(cpu, cpu->regs[X86_REG_EAX]);
		x86_cpu_push32(cpu, cpu->regs[X86_REG_ECX]);
		x86_cpu_push32(cpu, cpu->regs[X86_REG_EDX]);
		x86_cpu_push32(cpu, cpu->regs[X86_REG_EBX]);
		x86_cpu_push32(cpu, tmp_esp);
		x86_cpu_push32(cpu, cpu->regs[X86_REG_EBP]);
		x86_cpu_push32(cpu, cpu->regs[X86_REG_ESI]);
		x86_cpu_push32(cpu, cpu->regs[X86_REG_EDI]);
		break;
	}

	case INSN_POPA:
		cpu->regs[X86_REG_EDI] = x86_cpu_pop32(cpu);
		cpu->regs[X86_REG_ESI] = x86_cpu_pop32(cpu);
		cpu->regs[X86_REG_EBP] = x86_cpu_pop32(cpu);
		(void)x86_cpu_pop32(cpu); /* Skip ESP */
		cpu->regs[X86_REG_EBX] = x86_cpu_pop32(cpu);
		cpu->regs[X86_REG_EDX] = x86_cpu_pop32(cpu);
		cpu->regs[X86_REG_ECX] = x86_cpu_pop32(cpu);
		cpu->regs[X86_REG_EAX] = x86_cpu_pop32(cpu);
		break;

	case INSN_PUSHF:
		x86_cpu_push32(cpu, cpu->eflags & 0x00FCFFFF);
		break;

	case INSN_POPF:
		cpu->eflags = (x86_cpu_pop32(cpu) & 0x00FCFFFF) | 0x2;
		break;

	case INSN_ENTER:
	{
		uint16_t alloc_size = (uint16_t)insn->op[0].imm;
		uint8_t nesting = (uint8_t)insn->op[1].imm;
		x86_cpu_push32(cpu, cpu->regs[X86_REG_EBP]);
		uint32_t frame_ptr = cpu->regs[X86_REG_ESP];
		if (nesting > 0)
		{
			for (int i = 1; i < nesting; i++)
			{
				cpu->regs[X86_REG_EBP] -= 4;
				x86_cpu_push32(cpu, x86_cpu_read32(cpu, cpu->regs[X86_REG_EBP]));
			}
			x86_cpu_push32(cpu, frame_ptr);
		}
		cpu->regs[X86_REG_EBP] = frame_ptr;
		cpu->regs[X86_REG_ESP] -= alloc_size;
		break;
	}

	case INSN_LEAVE:
		cpu->regs[X86_REG_ESP] = cpu->regs[X86_REG_EBP];
		cpu->regs[X86_REG_EBP] = x86_cpu_pop32(cpu);
		break;

	/* --- Control flow --- */
	case INSN_JMP:
		if (insn->op[0].type == OP_REL)
			next_eip = next_eip + insn->op[0].rel;
		else
			next_eip = read_operand(cpu, &insn->op[0], pf);
		break;

	case INSN_Jcc:
		if (eval_cc(cpu->eflags, insn->cc))
			next_eip = next_eip + insn->op[0].rel;
		break;

	case INSN_CALL:
		if (insn->op[0].type == OP_REL)
		{
			x86_cpu_push32(cpu, next_eip);
			next_eip = next_eip + insn->op[0].rel;
		}
		else
		{
			a = read_operand(cpu, &insn->op[0], pf);
			x86_cpu_push32(cpu, next_eip);
			next_eip = a;
		}
		break;

	case INSN_RET:
		next_eip = x86_cpu_pop32(cpu);
		if (insn->num_ops > 0)
			cpu->regs[X86_REG_ESP] += insn->op[0].imm;
		break;

	case INSN_LOOP:
		cpu->regs[X86_REG_ECX]--;
		if (cpu->regs[X86_REG_ECX] != 0)
			next_eip = next_eip + insn->op[0].rel;
		break;

	case INSN_LOOPE:
		cpu->regs[X86_REG_ECX]--;
		if (cpu->regs[X86_REG_ECX] != 0 && (cpu->eflags & X86_ZF))
			next_eip = next_eip + insn->op[0].rel;
		break;

	case INSN_LOOPNE:
		cpu->regs[X86_REG_ECX]--;
		if (cpu->regs[X86_REG_ECX] != 0 && !(cpu->eflags & X86_ZF))
			next_eip = next_eip + insn->op[0].rel;
		break;

	/* INT 0x80 - Linux syscall */
	case INSN_INT:
		cpu->eip = next_eip;
		if (insn->op[0].imm == 0x80)
			return X86_EXIT_SYSCALL;
		return X86_EXIT_UNHANDLED;

	case INSN_INT3:
		cpu->eip = next_eip;
		return X86_EXIT_BREAKPOINT;

	case INSN_SYSENTER:
		cpu->eip = next_eip;
		return X86_EXIT_SYSCALL;

	/* --- String operations --- */
	case INSN_MOVS:
	{
		int sz = (insn->op_size == OPSZ_8) ? 1 : (insn->op_size == OPSZ_16) ? 2 : 4;
		int dir = (cpu->eflags & X86_DF) ? -sz : sz;
		uint32_t count = (pf & (PREFIX_REP | PREFIX_REPNE)) ? cpu->regs[X86_REG_ECX] : 1;
		while (count > 0)
		{
			if (sz == 1)
				x86_cpu_write8(cpu, cpu->regs[X86_REG_EDI], x86_cpu_read8(cpu, cpu->regs[X86_REG_ESI]));
			else if (sz == 2)
				x86_cpu_write16(cpu, cpu->regs[X86_REG_EDI], x86_cpu_read16(cpu, cpu->regs[X86_REG_ESI]));
			else
				x86_cpu_write32(cpu, cpu->regs[X86_REG_EDI], x86_cpu_read32(cpu, cpu->regs[X86_REG_ESI]));
			cpu->regs[X86_REG_ESI] += dir;
			cpu->regs[X86_REG_EDI] += dir;
			count--;
		}
		if (pf & (PREFIX_REP | PREFIX_REPNE))
			cpu->regs[X86_REG_ECX] = 0;
		break;
	}

	case INSN_STOS:
	{
		int sz = (insn->op_size == OPSZ_8) ? 1 : (insn->op_size == OPSZ_16) ? 2 : 4;
		int dir = (cpu->eflags & X86_DF) ? -sz : sz;
		uint32_t count = (pf & (PREFIX_REP | PREFIX_REPNE)) ? cpu->regs[X86_REG_ECX] : 1;
		while (count > 0)
		{
			if (sz == 1)
				x86_cpu_write8(cpu, cpu->regs[X86_REG_EDI], (uint8_t)cpu->regs[X86_REG_EAX]);
			else if (sz == 2)
				x86_cpu_write16(cpu, cpu->regs[X86_REG_EDI], (uint16_t)cpu->regs[X86_REG_EAX]);
			else
				x86_cpu_write32(cpu, cpu->regs[X86_REG_EDI], cpu->regs[X86_REG_EAX]);
			cpu->regs[X86_REG_EDI] += dir;
			count--;
		}
		if (pf & (PREFIX_REP | PREFIX_REPNE))
			cpu->regs[X86_REG_ECX] = 0;
		break;
	}

	case INSN_LODS:
	{
		int sz = (insn->op_size == OPSZ_8) ? 1 : (insn->op_size == OPSZ_16) ? 2 : 4;
		int dir = (cpu->eflags & X86_DF) ? -sz : sz;
		if (sz == 1)
			cpu->regs[X86_REG_EAX] = (cpu->regs[X86_REG_EAX] & 0xFFFFFF00) | x86_cpu_read8(cpu, cpu->regs[X86_REG_ESI]);
		else if (sz == 2)
			write_reg16(cpu, X86_REG_EAX, x86_cpu_read16(cpu, cpu->regs[X86_REG_ESI]));
		else
			cpu->regs[X86_REG_EAX] = x86_cpu_read32(cpu, cpu->regs[X86_REG_ESI]);
		cpu->regs[X86_REG_ESI] += dir;
		break;
	}

	case INSN_CMPS:
	{
		int sz = (insn->op_size == OPSZ_8) ? 1 : (insn->op_size == OPSZ_16) ? 2 : 4;
		int dir = (cpu->eflags & X86_DF) ? -sz : sz;
		bool rep = (pf & PREFIX_REP) != 0;
		bool repne = (pf & PREFIX_REPNE) != 0;
		uint32_t count = (rep || repne) ? cpu->regs[X86_REG_ECX] : 1;
		while (count > 0)
		{
			if (sz == 1) { a = x86_cpu_read8(cpu, cpu->regs[X86_REG_ESI]); b = x86_cpu_read8(cpu, cpu->regs[X86_REG_EDI]); }
			else if (sz == 2) { a = x86_cpu_read16(cpu, cpu->regs[X86_REG_ESI]); b = x86_cpu_read16(cpu, cpu->regs[X86_REG_EDI]); }
			else { a = x86_cpu_read32(cpu, cpu->regs[X86_REG_ESI]); b = x86_cpu_read32(cpu, cpu->regs[X86_REG_EDI]); }
			cpu->eflags = update_flags_sub(cpu->eflags, a, b, a - b, sz * 8);
			cpu->regs[X86_REG_ESI] += dir;
			cpu->regs[X86_REG_EDI] += dir;
			count--;
			if (rep && !(cpu->eflags & X86_ZF)) break;
			if (repne && (cpu->eflags & X86_ZF)) break;
		}
		if (rep || repne)
			cpu->regs[X86_REG_ECX] = count;
		break;
	}

	case INSN_SCAS:
	{
		int sz = (insn->op_size == OPSZ_8) ? 1 : (insn->op_size == OPSZ_16) ? 2 : 4;
		int dir = (cpu->eflags & X86_DF) ? -sz : sz;
		bool rep = (pf & PREFIX_REP) != 0;
		bool repne = (pf & PREFIX_REPNE) != 0;
		uint32_t count = (rep || repne) ? cpu->regs[X86_REG_ECX] : 1;
		a = (sz == 1) ? (cpu->regs[X86_REG_EAX] & 0xFF) : (sz == 2) ? (cpu->regs[X86_REG_EAX] & 0xFFFF) : cpu->regs[X86_REG_EAX];
		while (count > 0)
		{
			if (sz == 1) b = x86_cpu_read8(cpu, cpu->regs[X86_REG_EDI]);
			else if (sz == 2) b = x86_cpu_read16(cpu, cpu->regs[X86_REG_EDI]);
			else b = x86_cpu_read32(cpu, cpu->regs[X86_REG_EDI]);
			cpu->eflags = update_flags_sub(cpu->eflags, a, b, a - b, sz * 8);
			cpu->regs[X86_REG_EDI] += dir;
			count--;
			if (rep && !(cpu->eflags & X86_ZF)) break;
			if (repne && (cpu->eflags & X86_ZF)) break;
		}
		if (rep || repne)
			cpu->regs[X86_REG_ECX] = count;
		break;
	}

	/* --- Bit operations --- */
	case INSN_BT:
		a = read_operand(cpu, &insn->op[0], pf);
		b = read_operand(cpu, &insn->op[1], pf) & (bits - 1);
		if ((a >> b) & 1) cpu->eflags |= X86_CF; else cpu->eflags &= ~X86_CF;
		break;

	case INSN_BTS:
		a = read_operand(cpu, &insn->op[0], pf);
		b = read_operand(cpu, &insn->op[1], pf) & (bits - 1);
		if ((a >> b) & 1) cpu->eflags |= X86_CF; else cpu->eflags &= ~X86_CF;
		write_operand(cpu, &insn->op[0], a | (1u << b), pf);
		break;

	case INSN_BTR:
		a = read_operand(cpu, &insn->op[0], pf);
		b = read_operand(cpu, &insn->op[1], pf) & (bits - 1);
		if ((a >> b) & 1) cpu->eflags |= X86_CF; else cpu->eflags &= ~X86_CF;
		write_operand(cpu, &insn->op[0], a & ~(1u << b), pf);
		break;

	case INSN_BTC:
		a = read_operand(cpu, &insn->op[0], pf);
		b = read_operand(cpu, &insn->op[1], pf) & (bits - 1);
		if ((a >> b) & 1) cpu->eflags |= X86_CF; else cpu->eflags &= ~X86_CF;
		write_operand(cpu, &insn->op[0], a ^ (1u << b), pf);
		break;

	case INSN_BSF:
	{
		b = read_operand(cpu, &insn->op[1], pf) & mask;
		if (b == 0) { cpu->eflags |= X86_ZF; }
		else
		{
			cpu->eflags &= ~X86_ZF;
			uint32_t pos = 0;
			while (!(b & 1)) { b >>= 1; pos++; }
			write_operand(cpu, &insn->op[0], pos, pf);
		}
		break;
	}

	case INSN_BSR:
	{
		b = read_operand(cpu, &insn->op[1], pf) & mask;
		if (b == 0) { cpu->eflags |= X86_ZF; }
		else
		{
			cpu->eflags &= ~X86_ZF;
			uint32_t pos = bits - 1;
			uint32_t test_bit = 1u << pos;
			while (!(b & test_bit)) { test_bit >>= 1; pos--; }
			write_operand(cpu, &insn->op[0], pos, pf);
		}
		break;
	}

	case INSN_SETcc:
		write_operand(cpu, &insn->op[0], eval_cc(cpu->eflags, insn->cc) ? 1 : 0, pf);
		break;

	/* --- Flags --- */
	case INSN_STC: cpu->eflags |= X86_CF; break;
	case INSN_CLC: cpu->eflags &= ~X86_CF; break;
	case INSN_CMC: cpu->eflags ^= X86_CF; break;
	case INSN_STD: cpu->eflags |= X86_DF; break;
	case INSN_CLD: cpu->eflags &= ~X86_DF; break;
	case INSN_STI: cpu->eflags |= X86_IF; break;
	case INSN_CLI: cpu->eflags &= ~X86_IF; break;

	case INSN_SAHF:
		cpu->eflags = (cpu->eflags & ~0xFF) | (read_reg8(cpu, 4 /* AH */) & 0xD5) | 0x02;
		break;

	case INSN_LAHF:
		write_reg8(cpu, 4 /* AH */, (uint8_t)(cpu->eflags & 0xFF));
		break;

	/* --- Misc --- */
	case INSN_NOP:
		break;

	case INSN_HLT:
		cpu->eip = next_eip;
		cpu->halted = true;
		return X86_EXIT_HLT;

	case INSN_CPUID:
	{
		/* Minimal CPUID emulation for Linux */
		uint32_t leaf = cpu->regs[X86_REG_EAX];
		switch (leaf)
		{
		case 0: /* Vendor string */
			cpu->regs[X86_REG_EAX] = 1;
			cpu->regs[X86_REG_EBX] = 0x756E6547; /* "Genu" */
			cpu->regs[X86_REG_EDX] = 0x49656E69; /* "ineI" */
			cpu->regs[X86_REG_ECX] = 0x6C65746E; /* "ntel" */
			break;
		case 1: /* Feature flags */
			cpu->regs[X86_REG_EAX] = 0x00000601; /* Family 6, Model 0, Step 1 */
			cpu->regs[X86_REG_EBX] = 0;
			cpu->regs[X86_REG_ECX] = 0;
			cpu->regs[X86_REG_EDX] = (1 << 0) | (1 << 4) | (1 << 8) | (1 << 15) |
				(1 << 23) | (1 << 24) | (1 << 25); /* FPU, TSC, CX8, CMOV, MMX, FXSR, SSE */
			break;
		default:
			cpu->regs[X86_REG_EAX] = 0;
			cpu->regs[X86_REG_EBX] = 0;
			cpu->regs[X86_REG_ECX] = 0;
			cpu->regs[X86_REG_EDX] = 0;
			break;
		}
		break;
	}

	case INSN_RDTSC:
	{
		uint64_t tsc = cpu->total_insn_count;
		cpu->regs[X86_REG_EAX] = (uint32_t)tsc;
		cpu->regs[X86_REG_EDX] = (uint32_t)(tsc >> 32);
		break;
	}

	case INSN_UD2:
		cpu->eip = next_eip;
		return X86_EXIT_FAULT;

	case INSN_MOV_SEG:
		/* Simplified: just track the segment selector values */
		if ((insn->modrm >> 3) & 7)
		{
			/* Move from sreg */
			uint8_t seg = (insn->modrm >> 3) & 7;
			if (seg < X86_SEG_COUNT)
				write_operand(cpu, &insn->op[0], cpu->segs[seg], pf);
		}
		else
		{
			/* Move to sreg */
			uint8_t seg = (insn->modrm >> 3) & 7;
			if (seg < X86_SEG_COUNT)
				cpu->segs[seg] = (uint16_t)read_operand(cpu, &insn->op[1], pf);
		}
		break;

	case INSN_XADD:
		a = read_operand(cpu, &insn->op[0], pf);
		b = read_operand(cpu, &insn->op[1], pf);
		result = a + b;
		write_operand(cpu, &insn->op[1], a, pf);
		write_operand(cpu, &insn->op[0], result, pf);
		cpu->eflags = update_flags_add(cpu->eflags, a, b, result, bits);
		break;

	case INSN_CMPXCHG:
		a = read_operand(cpu, &insn->op[0], pf);
		b = (bits == 8) ? (cpu->regs[X86_REG_EAX] & 0xFF) :
		    (bits == 16) ? (cpu->regs[X86_REG_EAX] & 0xFFFF) : cpu->regs[X86_REG_EAX];
		result = b - a;
		cpu->eflags = update_flags_sub(cpu->eflags, b, a, result, bits);
		if ((b & mask) == (a & mask))
		{
			uint32_t src = read_operand(cpu, &insn->op[1], pf);
			write_operand(cpu, &insn->op[0], src, pf);
		}
		else
		{
			if (bits == 8) cpu->regs[X86_REG_EAX] = (cpu->regs[X86_REG_EAX] & 0xFFFFFF00) | (a & 0xFF);
			else if (bits == 16) write_reg16(cpu, X86_REG_EAX, (uint16_t)a);
			else cpu->regs[X86_REG_EAX] = a;
		}
		break;

	/* FPU / SSE - stub for now, log unhandled */
	case INSN_FPU:
	case INSN_SSE:
	case INSN_WAIT:
		/* Silently ignore FPU/SSE for now - many programs work without */
		break;

	case INSN_INVALID:
	default:
		log_error("DBT: Unhandled instruction at EIP=%08x opcode=%02x", cpu->eip, insn->opcode[0]);
		cpu->eip = next_eip;
		return X86_EXIT_UNHANDLED;
	}

	cpu->eip = next_eip;
	return (enum x86_exit_reason)-1; /* Continue execution */
}

/* ===== Main interpreter loop ===== */

enum x86_exit_reason x86_interp_step(struct x86_cpu *cpu)
{
	struct x86_insn insn;
	uint8_t *code = (uint8_t *)x86_cpu_guest_to_host(cpu, cpu->eip);
	int len = x86_decode(code, X86_MAX_INSN_LEN, cpu->eip, &insn);

	if (len == 0 || insn.type == INSN_INVALID)
	{
		log_error("DBT: Failed to decode instruction at EIP=%08x", cpu->eip);
		cpu->exit_reason = X86_EXIT_FAULT;
		return X86_EXIT_FAULT;
	}

	enum x86_exit_reason reason = exec_insn(cpu, &insn);
	cpu->insn_count = 1;
	cpu->total_insn_count++;

	if ((int)reason == -1)
		return X86_EXIT_SINGLE_STEP; /* Completed normally */

	cpu->exit_reason = reason;
	return reason;
}

enum x86_exit_reason x86_interp_run(struct x86_cpu *cpu, uint64_t max_insns)
{
	struct x86_insn insn;
	uint64_t count = 0;

	while (!cpu->halted)
	{
		uint8_t *code = (uint8_t *)x86_cpu_guest_to_host(cpu, cpu->eip);
		int len = x86_decode(code, X86_MAX_INSN_LEN, cpu->eip, &insn);

		if (len == 0 || insn.type == INSN_INVALID)
		{
			log_error("DBT: Failed to decode at EIP=%08x (byte=%02x)", cpu->eip, *code);
			cpu->exit_reason = X86_EXIT_FAULT;
			cpu->insn_count = count;
			return X86_EXIT_FAULT;
		}

		enum x86_exit_reason reason = exec_insn(cpu, &insn);
		count++;
		cpu->total_insn_count++;

		if ((int)reason != -1)
		{
			cpu->exit_reason = reason;
			cpu->insn_count = count;
			return reason;
		}

		if (max_insns > 0 && count >= max_insns)
		{
			cpu->exit_reason = X86_EXIT_SINGLE_STEP;
			cpu->insn_count = count;
			return X86_EXIT_SINGLE_STEP;
		}
	}

	cpu->exit_reason = X86_EXIT_HLT;
	cpu->insn_count = count;
	return X86_EXIT_HLT;
}
