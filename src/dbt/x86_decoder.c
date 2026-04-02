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
 * x86 Instruction Decoder
 *
 * Decodes 32-bit (IA-32) x86 instructions from a byte stream.
 * Handles prefixes, ModR/M, SIB, displacement, and immediate fields.
 */

#include <dbt/x86_decoder.h>
#include <string.h>

/* Helper to read bytes from the instruction stream */
struct decode_state
{
	const uint8_t *code;
	int pos;
	int max_len;
};

static inline uint8_t read8(struct decode_state *s)
{
	if (s->pos >= s->max_len)
		return 0;
	return s->code[s->pos++];
}

static inline uint16_t read16(struct decode_state *s)
{
	uint16_t val;
	if (s->pos + 2 > s->max_len)
		return 0;
	memcpy(&val, &s->code[s->pos], 2);
	s->pos += 2;
	return val;
}

static inline uint32_t read32(struct decode_state *s)
{
	uint32_t val;
	if (s->pos + 4 > s->max_len)
		return 0;
	memcpy(&val, &s->code[s->pos], 4);
	s->pos += 4;
	return val;
}

/* Decode ModR/M and SIB bytes, fill in operand structures */
static void decode_modrm(struct decode_state *s, struct x86_insn *insn,
	struct x86_operand *reg_op, struct x86_operand *rm_op, enum x86_op_size size)
{
	uint8_t modrm = read8(s);
	insn->has_modrm = true;
	insn->modrm = modrm;

	uint8_t mod = (modrm >> 6) & 3;
	uint8_t reg = (modrm >> 3) & 7;
	uint8_t rm = modrm & 7;

	/* reg operand */
	if (reg_op)
	{
		reg_op->type = OP_REG;
		reg_op->reg = reg;
		reg_op->size = size;
	}

	/* r/m operand */
	if (rm_op)
	{
		rm_op->size = size;

		if (mod == 3)
		{
			/* Register direct */
			rm_op->type = OP_REG;
			rm_op->reg = rm;
		}
		else
		{
			/* Memory */
			rm_op->type = OP_MEM;
			rm_op->mem.base_reg = -1;
			rm_op->mem.index_reg = -1;
			rm_op->mem.scale = 1;
			rm_op->mem.disp = 0;
			rm_op->mem.seg = 0xFF; /* Default segment */

			if (rm == 4)
			{
				/* SIB byte follows */
				uint8_t sib = read8(s);
				insn->sib = sib;
				uint8_t ss = (sib >> 6) & 3;
				uint8_t idx = (sib >> 3) & 7;
				uint8_t base = sib & 7;

				rm_op->mem.scale = 1 << ss;
				if (idx != 4) /* ESP cannot be index */
					rm_op->mem.index_reg = idx;
				if (base == 5 && mod == 0)
				{
					/* disp32, no base */
					rm_op->mem.disp = (int32_t)read32(s);
				}
				else
				{
					rm_op->mem.base_reg = base;
				}
			}
			else if (rm == 5 && mod == 0)
			{
				/* disp32 only (no base register) */
				rm_op->mem.disp = (int32_t)read32(s);
			}
			else
			{
				rm_op->mem.base_reg = rm;
			}

			/* Displacement */
			if (mod == 1)
				rm_op->mem.disp = (int8_t)read8(s);
			else if (mod == 2)
				rm_op->mem.disp = (int32_t)read32(s);
		}
	}
}

/* ALU instruction group (ADD, OR, ADC, SBB, AND, SUB, XOR, CMP) */
static const enum x86_insn_type alu_group[8] = {
	INSN_ADD, INSN_OR, INSN_ADC, INSN_SBB, INSN_AND, INSN_SUB, INSN_XOR, INSN_CMP
};

/* Shift/rotate group (ROL, ROR, RCL, RCR, SHL, SHR, -, SAR) */
static const enum x86_insn_type shift_group[8] = {
	INSN_ROL, INSN_ROR, INSN_RCL, INSN_RCR, INSN_SHL, INSN_SHR, INSN_INVALID, INSN_SAR
};

int x86_decode(const uint8_t *code, int max_len, uint32_t addr, struct x86_insn *insn)
{
	struct decode_state state = { code, 0, max_len };
	struct decode_state *s = &state;

	memset(insn, 0, sizeof(*insn));
	insn->addr = addr;
	insn->type = INSN_INVALID;
	insn->op_size = OPSZ_32;
	insn->addr_size = OPSZ_32;

	if (max_len <= 0)
		return 0;

	/* --- Phase 1: Decode prefixes --- */
	bool done_prefix = false;
	while (!done_prefix && s->pos < s->max_len)
	{
		uint8_t b = s->code[s->pos];
		switch (b)
		{
		case 0xF0: insn->prefixes |= PREFIX_LOCK; s->pos++; break;
		case 0xF2: insn->prefixes |= PREFIX_REPNE; s->pos++; break;
		case 0xF3: insn->prefixes |= PREFIX_REP; s->pos++; break;
		case 0x26: insn->prefixes |= PREFIX_SEG_ES; s->pos++; break;
		case 0x2E: insn->prefixes |= PREFIX_SEG_CS; s->pos++; break;
		case 0x36: insn->prefixes |= PREFIX_SEG_SS; s->pos++; break;
		case 0x3E: insn->prefixes |= PREFIX_SEG_DS; s->pos++; break;
		case 0x64: insn->prefixes |= PREFIX_SEG_FS; s->pos++; break;
		case 0x65: insn->prefixes |= PREFIX_SEG_GS; s->pos++; break;
		case 0x66: insn->prefixes |= PREFIX_OPSIZE; insn->op_size = OPSZ_16; s->pos++; break;
		case 0x67: insn->prefixes |= PREFIX_ADDRSIZE; insn->addr_size = OPSZ_16; s->pos++; break;
		default: done_prefix = true; break;
		}
	}

	if (s->pos >= s->max_len)
		return 0;

	/* Determine operand size shorthand */
	enum x86_op_size opsz = insn->op_size;

	/* --- Phase 2: Decode opcode and operands --- */
	uint8_t opcode = read8(s);
	insn->opcode[0] = opcode;
	insn->opcode_len = 1;

	switch (opcode)
	{
	/* ALU r/m8, r8 and r/m32, r32 */
	case 0x00: case 0x01: case 0x02: case 0x03:
	case 0x08: case 0x09: case 0x0A: case 0x0B:
	case 0x10: case 0x11: case 0x12: case 0x13:
	case 0x18: case 0x19: case 0x1A: case 0x1B:
	case 0x20: case 0x21: case 0x22: case 0x23:
	case 0x28: case 0x29: case 0x2A: case 0x2B:
	case 0x30: case 0x31: case 0x32: case 0x33:
	case 0x38: case 0x39: case 0x3A: case 0x3B:
	{
		int alu_idx = (opcode >> 3) & 7;
		int direction = (opcode >> 1) & 1; /* 0=r/m,r  1=r,r/m */
		int is_byte = !(opcode & 1);
		enum x86_op_size sz = is_byte ? OPSZ_8 : opsz;
		insn->type = alu_group[alu_idx];
		insn->num_ops = 2;
		if (direction)
			decode_modrm(s, insn, &insn->op[0], &insn->op[1], sz);
		else
			decode_modrm(s, insn, &insn->op[1], &insn->op[0], sz);
		break;
	}

	/* ALU AL/EAX, imm8/imm32 */
	case 0x04: case 0x05: case 0x0C: case 0x0D:
	case 0x14: case 0x15: case 0x1C: case 0x1D:
	case 0x24: case 0x25: case 0x2C: case 0x2D:
	case 0x34: case 0x35: case 0x3C: case 0x3D:
	{
		int alu_idx = (opcode >> 3) & 7;
		int is_byte = !(opcode & 1);
		enum x86_op_size sz = is_byte ? OPSZ_8 : opsz;
		insn->type = alu_group[alu_idx];
		insn->num_ops = 2;
		insn->op[0].type = OP_REG;
		insn->op[0].reg = X86_REG_EAX;
		insn->op[0].size = sz;
		insn->op[1].type = OP_IMM;
		insn->op[1].size = sz;
		insn->op[1].imm = is_byte ? read8(s) : (opsz == OPSZ_16 ? read16(s) : read32(s));
		break;
	}

	/* INC/DEC register (0x40-0x4F) */
	case 0x40: case 0x41: case 0x42: case 0x43:
	case 0x44: case 0x45: case 0x46: case 0x47:
		insn->type = INSN_INC;
		insn->num_ops = 1;
		insn->op[0].type = OP_REG;
		insn->op[0].reg = opcode & 7;
		insn->op[0].size = opsz;
		break;
	case 0x48: case 0x49: case 0x4A: case 0x4B:
	case 0x4C: case 0x4D: case 0x4E: case 0x4F:
		insn->type = INSN_DEC;
		insn->num_ops = 1;
		insn->op[0].type = OP_REG;
		insn->op[0].reg = opcode & 7;
		insn->op[0].size = opsz;
		break;

	/* PUSH register */
	case 0x50: case 0x51: case 0x52: case 0x53:
	case 0x54: case 0x55: case 0x56: case 0x57:
		insn->type = INSN_PUSH;
		insn->num_ops = 1;
		insn->op[0].type = OP_REG;
		insn->op[0].reg = opcode & 7;
		insn->op[0].size = opsz;
		break;

	/* POP register */
	case 0x58: case 0x59: case 0x5A: case 0x5B:
	case 0x5C: case 0x5D: case 0x5E: case 0x5F:
		insn->type = INSN_POP;
		insn->num_ops = 1;
		insn->op[0].type = OP_REG;
		insn->op[0].reg = opcode & 7;
		insn->op[0].size = opsz;
		break;

	/* PUSHA/POPA */
	case 0x60: insn->type = INSN_PUSHA; insn->num_ops = 0; break;
	case 0x61: insn->type = INSN_POPA; insn->num_ops = 0; break;

	/* PUSH imm32 */
	case 0x68:
		insn->type = INSN_PUSH;
		insn->num_ops = 1;
		insn->op[0].type = OP_IMM;
		insn->op[0].size = opsz;
		insn->op[0].imm = (opsz == OPSZ_16) ? read16(s) : read32(s);
		break;

	/* IMUL r, r/m, imm32 */
	case 0x69:
		insn->type = INSN_IMUL3;
		insn->num_ops = 3;
		decode_modrm(s, insn, &insn->op[0], &insn->op[1], opsz);
		insn->op[2].type = OP_IMM;
		insn->op[2].size = opsz;
		insn->op[2].imm = (opsz == OPSZ_16) ? read16(s) : read32(s);
		break;

	/* PUSH imm8 (sign-extended) */
	case 0x6A:
		insn->type = INSN_PUSH;
		insn->num_ops = 1;
		insn->op[0].type = OP_IMM;
		insn->op[0].size = OPSZ_8;
		insn->op[0].imm = (int8_t)read8(s);
		break;

	/* IMUL r, r/m, imm8 */
	case 0x6B:
		insn->type = INSN_IMUL3;
		insn->num_ops = 3;
		decode_modrm(s, insn, &insn->op[0], &insn->op[1], opsz);
		insn->op[2].type = OP_IMM;
		insn->op[2].size = OPSZ_8;
		insn->op[2].imm = (int8_t)read8(s);
		break;

	/* Short conditional jumps (Jcc rel8) */
	case 0x70: case 0x71: case 0x72: case 0x73:
	case 0x74: case 0x75: case 0x76: case 0x77:
	case 0x78: case 0x79: case 0x7A: case 0x7B:
	case 0x7C: case 0x7D: case 0x7E: case 0x7F:
		insn->type = INSN_Jcc;
		insn->cc = (enum x86_cc)(opcode & 0x0F);
		insn->num_ops = 1;
		insn->op[0].type = OP_REL;
		insn->op[0].size = OPSZ_8;
		insn->op[0].rel = (int8_t)read8(s);
		break;

	/* Group 1: ALU r/m, imm */
	case 0x80: /* r/m8, imm8 */
	case 0x81: /* r/m32, imm32 */
	case 0x83: /* r/m32, imm8 (sign-extended) */
	{
		enum x86_op_size sz = (opcode == 0x80) ? OPSZ_8 : opsz;
		decode_modrm(s, insn, NULL, &insn->op[0], sz);
		int grp = (insn->modrm >> 3) & 7;
		insn->type = alu_group[grp];
		insn->num_ops = 2;
		insn->op[1].type = OP_IMM;
		if (opcode == 0x80)
		{
			insn->op[1].size = OPSZ_8;
			insn->op[1].imm = read8(s);
		}
		else if (opcode == 0x83)
		{
			insn->op[1].size = OPSZ_8;
			insn->op[1].imm = (int8_t)read8(s);
		}
		else
		{
			insn->op[1].size = sz;
			insn->op[1].imm = (opsz == OPSZ_16) ? read16(s) : read32(s);
		}
		break;
	}

	/* TEST r/m8,r8 and r/m32,r32 */
	case 0x84:
		insn->type = INSN_TEST;
		insn->num_ops = 2;
		decode_modrm(s, insn, &insn->op[1], &insn->op[0], OPSZ_8);
		break;
	case 0x85:
		insn->type = INSN_TEST;
		insn->num_ops = 2;
		decode_modrm(s, insn, &insn->op[1], &insn->op[0], opsz);
		break;

	/* XCHG r/m,r */
	case 0x86:
		insn->type = INSN_XCHG;
		insn->num_ops = 2;
		decode_modrm(s, insn, &insn->op[1], &insn->op[0], OPSZ_8);
		break;
	case 0x87:
		insn->type = INSN_XCHG;
		insn->num_ops = 2;
		decode_modrm(s, insn, &insn->op[1], &insn->op[0], opsz);
		break;

	/* MOV r/m,r and r,r/m */
	case 0x88:
		insn->type = INSN_MOV;
		insn->num_ops = 2;
		decode_modrm(s, insn, &insn->op[1], &insn->op[0], OPSZ_8);
		break;
	case 0x89:
		insn->type = INSN_MOV;
		insn->num_ops = 2;
		decode_modrm(s, insn, &insn->op[1], &insn->op[0], opsz);
		break;
	case 0x8A:
		insn->type = INSN_MOV;
		insn->num_ops = 2;
		decode_modrm(s, insn, &insn->op[0], &insn->op[1], OPSZ_8);
		break;
	case 0x8B:
		insn->type = INSN_MOV;
		insn->num_ops = 2;
		decode_modrm(s, insn, &insn->op[0], &insn->op[1], opsz);
		break;

	/* MOV r/m16, Sreg */
	case 0x8C:
		insn->type = INSN_MOV_SEG;
		insn->num_ops = 2;
		decode_modrm(s, insn, &insn->op[1], &insn->op[0], OPSZ_16);
		break;

	/* LEA r, m */
	case 0x8D:
		insn->type = INSN_LEA;
		insn->num_ops = 2;
		decode_modrm(s, insn, &insn->op[0], &insn->op[1], opsz);
		break;

	/* MOV Sreg, r/m16 */
	case 0x8E:
		insn->type = INSN_MOV_SEG;
		insn->num_ops = 2;
		decode_modrm(s, insn, &insn->op[0], &insn->op[1], OPSZ_16);
		break;

	/* NOP (0x90) or XCHG eax, reg */
	case 0x90:
		insn->type = INSN_NOP;
		insn->num_ops = 0;
		break;
	case 0x91: case 0x92: case 0x93:
	case 0x94: case 0x95: case 0x96: case 0x97:
		insn->type = INSN_XCHG;
		insn->num_ops = 2;
		insn->op[0].type = OP_REG;
		insn->op[0].reg = X86_REG_EAX;
		insn->op[0].size = opsz;
		insn->op[1].type = OP_REG;
		insn->op[1].reg = opcode & 7;
		insn->op[1].size = opsz;
		break;

	/* CBW/CWDE */
	case 0x98:
		insn->type = INSN_CBW;
		insn->num_ops = 0;
		break;

	/* CWD/CDQ */
	case 0x99:
		insn->type = INSN_CDQ;
		insn->num_ops = 0;
		break;

	/* PUSHF */
	case 0x9C: insn->type = INSN_PUSHF; insn->num_ops = 0; break;
	/* POPF */
	case 0x9D: insn->type = INSN_POPF; insn->num_ops = 0; break;
	/* SAHF */
	case 0x9E: insn->type = INSN_SAHF; insn->num_ops = 0; break;
	/* LAHF */
	case 0x9F: insn->type = INSN_LAHF; insn->num_ops = 0; break;

	/* MOV AL/EAX, moffs */
	case 0xA0:
		insn->type = INSN_MOV;
		insn->num_ops = 2;
		insn->op[0].type = OP_REG;
		insn->op[0].reg = X86_REG_EAX;
		insn->op[0].size = OPSZ_8;
		insn->op[1].type = OP_MEM;
		insn->op[1].size = OPSZ_8;
		insn->op[1].mem.base_reg = -1;
		insn->op[1].mem.index_reg = -1;
		insn->op[1].mem.scale = 1;
		insn->op[1].mem.disp = read32(s);
		insn->op[1].mem.seg = 0xFF;
		break;
	case 0xA1:
		insn->type = INSN_MOV;
		insn->num_ops = 2;
		insn->op[0].type = OP_REG;
		insn->op[0].reg = X86_REG_EAX;
		insn->op[0].size = opsz;
		insn->op[1].type = OP_MEM;
		insn->op[1].size = opsz;
		insn->op[1].mem.base_reg = -1;
		insn->op[1].mem.index_reg = -1;
		insn->op[1].mem.scale = 1;
		insn->op[1].mem.disp = read32(s);
		insn->op[1].mem.seg = 0xFF;
		break;

	/* MOV moffs, AL/EAX */
	case 0xA2:
		insn->type = INSN_MOV;
		insn->num_ops = 2;
		insn->op[0].type = OP_MEM;
		insn->op[0].size = OPSZ_8;
		insn->op[0].mem.base_reg = -1;
		insn->op[0].mem.index_reg = -1;
		insn->op[0].mem.scale = 1;
		insn->op[0].mem.disp = read32(s);
		insn->op[0].mem.seg = 0xFF;
		insn->op[1].type = OP_REG;
		insn->op[1].reg = X86_REG_EAX;
		insn->op[1].size = OPSZ_8;
		break;
	case 0xA3:
		insn->type = INSN_MOV;
		insn->num_ops = 2;
		insn->op[0].type = OP_MEM;
		insn->op[0].size = opsz;
		insn->op[0].mem.base_reg = -1;
		insn->op[0].mem.index_reg = -1;
		insn->op[0].mem.scale = 1;
		insn->op[0].mem.disp = read32(s);
		insn->op[0].mem.seg = 0xFF;
		insn->op[1].type = OP_REG;
		insn->op[1].reg = X86_REG_EAX;
		insn->op[1].size = opsz;
		break;

	/* MOVS/CMPS/STOS/LODS/SCAS */
	case 0xA4: insn->type = INSN_MOVS; insn->op_size = OPSZ_8; insn->num_ops = 0; break;
	case 0xA5: insn->type = INSN_MOVS; insn->num_ops = 0; break;
	case 0xA6: insn->type = INSN_CMPS; insn->op_size = OPSZ_8; insn->num_ops = 0; break;
	case 0xA7: insn->type = INSN_CMPS; insn->num_ops = 0; break;

	/* TEST AL/EAX, imm */
	case 0xA8:
		insn->type = INSN_TEST;
		insn->num_ops = 2;
		insn->op[0].type = OP_REG;
		insn->op[0].reg = X86_REG_EAX;
		insn->op[0].size = OPSZ_8;
		insn->op[1].type = OP_IMM;
		insn->op[1].size = OPSZ_8;
		insn->op[1].imm = read8(s);
		break;
	case 0xA9:
		insn->type = INSN_TEST;
		insn->num_ops = 2;
		insn->op[0].type = OP_REG;
		insn->op[0].reg = X86_REG_EAX;
		insn->op[0].size = opsz;
		insn->op[1].type = OP_IMM;
		insn->op[1].size = opsz;
		insn->op[1].imm = (opsz == OPSZ_16) ? read16(s) : read32(s);
		break;

	/* STOS/LODS/SCAS */
	case 0xAA: insn->type = INSN_STOS; insn->op_size = OPSZ_8; insn->num_ops = 0; break;
	case 0xAB: insn->type = INSN_STOS; insn->num_ops = 0; break;
	case 0xAC: insn->type = INSN_LODS; insn->op_size = OPSZ_8; insn->num_ops = 0; break;
	case 0xAD: insn->type = INSN_LODS; insn->num_ops = 0; break;
	case 0xAE: insn->type = INSN_SCAS; insn->op_size = OPSZ_8; insn->num_ops = 0; break;
	case 0xAF: insn->type = INSN_SCAS; insn->num_ops = 0; break;

	/* MOV r8, imm8 */
	case 0xB0: case 0xB1: case 0xB2: case 0xB3:
	case 0xB4: case 0xB5: case 0xB6: case 0xB7:
		insn->type = INSN_MOV;
		insn->num_ops = 2;
		insn->op[0].type = OP_REG;
		insn->op[0].reg = opcode & 7;
		insn->op[0].size = OPSZ_8;
		insn->op[1].type = OP_IMM;
		insn->op[1].size = OPSZ_8;
		insn->op[1].imm = read8(s);
		break;

	/* MOV r32, imm32 */
	case 0xB8: case 0xB9: case 0xBA: case 0xBB:
	case 0xBC: case 0xBD: case 0xBE: case 0xBF:
		insn->type = INSN_MOV;
		insn->num_ops = 2;
		insn->op[0].type = OP_REG;
		insn->op[0].reg = opcode & 7;
		insn->op[0].size = opsz;
		insn->op[1].type = OP_IMM;
		insn->op[1].size = opsz;
		insn->op[1].imm = (opsz == OPSZ_16) ? read16(s) : read32(s);
		break;

	/* Shift group: r/m, imm8 */
	case 0xC0: case 0xC1:
	{
		enum x86_op_size sz = (opcode == 0xC0) ? OPSZ_8 : opsz;
		decode_modrm(s, insn, NULL, &insn->op[0], sz);
		int grp = (insn->modrm >> 3) & 7;
		insn->type = shift_group[grp];
		insn->num_ops = 2;
		insn->op[1].type = OP_IMM;
		insn->op[1].size = OPSZ_8;
		insn->op[1].imm = read8(s);
		break;
	}

	/* RET imm16 / RET */
	case 0xC2:
		insn->type = INSN_RET;
		insn->num_ops = 1;
		insn->op[0].type = OP_IMM;
		insn->op[0].size = OPSZ_16;
		insn->op[0].imm = read16(s);
		break;
	case 0xC3:
		insn->type = INSN_RET;
		insn->num_ops = 0;
		break;

	/* MOV r/m, imm */
	case 0xC6:
		insn->type = INSN_MOV;
		insn->num_ops = 2;
		decode_modrm(s, insn, NULL, &insn->op[0], OPSZ_8);
		insn->op[1].type = OP_IMM;
		insn->op[1].size = OPSZ_8;
		insn->op[1].imm = read8(s);
		break;
	case 0xC7:
		insn->type = INSN_MOV;
		insn->num_ops = 2;
		decode_modrm(s, insn, NULL, &insn->op[0], opsz);
		insn->op[1].type = OP_IMM;
		insn->op[1].size = opsz;
		insn->op[1].imm = (opsz == OPSZ_16) ? read16(s) : read32(s);
		break;

	/* ENTER */
	case 0xC8:
		insn->type = INSN_ENTER;
		insn->num_ops = 2;
		insn->op[0].type = OP_IMM;
		insn->op[0].size = OPSZ_16;
		insn->op[0].imm = read16(s);
		insn->op[1].type = OP_IMM;
		insn->op[1].size = OPSZ_8;
		insn->op[1].imm = read8(s);
		break;

	/* LEAVE */
	case 0xC9: insn->type = INSN_LEAVE; insn->num_ops = 0; break;

	/* INT imm8 */
	case 0xCD:
		insn->type = INSN_INT;
		insn->num_ops = 1;
		insn->op[0].type = OP_IMM;
		insn->op[0].size = OPSZ_8;
		insn->op[0].imm = read8(s);
		break;

	/* INT3 */
	case 0xCC:
		insn->type = INSN_INT3;
		insn->num_ops = 0;
		break;

	/* IRET */
	case 0xCF:
		insn->type = INSN_IRET;
		insn->num_ops = 0;
		break;

	/* Shift group: r/m, 1 */
	case 0xD0: case 0xD1:
	{
		enum x86_op_size sz = (opcode == 0xD0) ? OPSZ_8 : opsz;
		decode_modrm(s, insn, NULL, &insn->op[0], sz);
		int grp = (insn->modrm >> 3) & 7;
		insn->type = shift_group[grp];
		insn->num_ops = 2;
		insn->op[1].type = OP_IMM;
		insn->op[1].size = OPSZ_8;
		insn->op[1].imm = 1;
		break;
	}

	/* Shift group: r/m, CL */
	case 0xD2: case 0xD3:
	{
		enum x86_op_size sz = (opcode == 0xD2) ? OPSZ_8 : opsz;
		decode_modrm(s, insn, NULL, &insn->op[0], sz);
		int grp = (insn->modrm >> 3) & 7;
		insn->type = shift_group[grp];
		insn->num_ops = 2;
		insn->op[1].type = OP_REG;
		insn->op[1].reg = X86_REG_ECX;
		insn->op[1].size = OPSZ_8;
		break;
	}

	/* FPU escape (D8-DF) */
	case 0xD8: case 0xD9: case 0xDA: case 0xDB:
	case 0xDC: case 0xDD: case 0xDE: case 0xDF:
		insn->type = INSN_FPU;
		/* Store the sub-opcode for FPU instruction selection */
		decode_modrm(s, insn, NULL, &insn->op[0], OPSZ_32);
		insn->fpu_opcode = ((opcode & 7) << 8) | insn->modrm;
		insn->num_ops = 1;
		break;

	/* LOOP/LOOPcc/JECXZ rel8 */
	case 0xE0: insn->type = INSN_LOOPNE; insn->num_ops = 1; goto rel8;
	case 0xE1: insn->type = INSN_LOOPE; insn->num_ops = 1; goto rel8;
	case 0xE2: insn->type = INSN_LOOP; insn->num_ops = 1; goto rel8;
	case 0xE3: insn->type = INSN_Jcc; insn->cc = CC_Z; insn->num_ops = 1; /* JECXZ */
	rel8:
		insn->op[0].type = OP_REL;
		insn->op[0].size = OPSZ_8;
		insn->op[0].rel = (int8_t)read8(s);
		break;

	/* CALL rel32 */
	case 0xE8:
		insn->type = INSN_CALL;
		insn->num_ops = 1;
		insn->op[0].type = OP_REL;
		insn->op[0].size = opsz;
		insn->op[0].rel = (opsz == OPSZ_16) ? (int16_t)read16(s) : (int32_t)read32(s);
		break;

	/* JMP rel32 */
	case 0xE9:
		insn->type = INSN_JMP;
		insn->num_ops = 1;
		insn->op[0].type = OP_REL;
		insn->op[0].size = opsz;
		insn->op[0].rel = (opsz == OPSZ_16) ? (int16_t)read16(s) : (int32_t)read32(s);
		break;

	/* JMP rel8 */
	case 0xEB:
		insn->type = INSN_JMP;
		insn->num_ops = 1;
		insn->op[0].type = OP_REL;
		insn->op[0].size = OPSZ_8;
		insn->op[0].rel = (int8_t)read8(s);
		break;

	/* HLT */
	case 0xF4: insn->type = INSN_HLT; insn->num_ops = 0; break;

	/* CMC/CLC/STC/CLI/STI/CLD/STD */
	case 0xF5: insn->type = INSN_CMC; insn->num_ops = 0; break;
	case 0xF8: insn->type = INSN_CLC; insn->num_ops = 0; break;
	case 0xF9: insn->type = INSN_STC; insn->num_ops = 0; break;
	case 0xFA: insn->type = INSN_CLI; insn->num_ops = 0; break;
	case 0xFB: insn->type = INSN_STI; insn->num_ops = 0; break;
	case 0xFC: insn->type = INSN_CLD; insn->num_ops = 0; break;
	case 0xFD: insn->type = INSN_STD; insn->num_ops = 0; break;

	/* Group 3: TEST/NOT/NEG/MUL/IMUL/DIV/IDIV */
	case 0xF6: case 0xF7:
	{
		enum x86_op_size sz = (opcode == 0xF6) ? OPSZ_8 : opsz;
		decode_modrm(s, insn, NULL, &insn->op[0], sz);
		int grp = (insn->modrm >> 3) & 7;
		switch (grp)
		{
		case 0: /* TEST r/m, imm */
			insn->type = INSN_TEST;
			insn->num_ops = 2;
			insn->op[1].type = OP_IMM;
			insn->op[1].size = sz;
			if (opcode == 0xF6)
				insn->op[1].imm = read8(s);
			else
				insn->op[1].imm = (opsz == OPSZ_16) ? read16(s) : read32(s);
			break;
		case 2: insn->type = INSN_NOT; insn->num_ops = 1; break;
		case 3: insn->type = INSN_NEG; insn->num_ops = 1; break;
		case 4: insn->type = INSN_MUL; insn->num_ops = 1; break;
		case 5: insn->type = INSN_IMUL; insn->num_ops = 1; break;
		case 6: insn->type = INSN_DIV; insn->num_ops = 1; break;
		case 7: insn->type = INSN_IDIV; insn->num_ops = 1; break;
		default: insn->type = INSN_INVALID; break;
		}
		break;
	}

	/* Group 4/5: INC/DEC/CALL/JMP/PUSH r/m */
	case 0xFE:
	{
		decode_modrm(s, insn, NULL, &insn->op[0], OPSZ_8);
		int grp = (insn->modrm >> 3) & 7;
		switch (grp)
		{
		case 0: insn->type = INSN_INC; break;
		case 1: insn->type = INSN_DEC; break;
		default: insn->type = INSN_INVALID; break;
		}
		insn->num_ops = 1;
		break;
	}
	case 0xFF:
	{
		decode_modrm(s, insn, NULL, &insn->op[0], opsz);
		int grp = (insn->modrm >> 3) & 7;
		switch (grp)
		{
		case 0: insn->type = INSN_INC; break;
		case 1: insn->type = INSN_DEC; break;
		case 2: insn->type = INSN_CALL; break;
		case 4: insn->type = INSN_JMP; break;
		case 6: insn->type = INSN_PUSH; break;
		default: insn->type = INSN_INVALID; break;
		}
		insn->num_ops = 1;
		break;
	}

	/* WAIT/FWAIT */
	case 0x9B: insn->type = INSN_WAIT; insn->num_ops = 0; break;

	/* Two-byte opcodes (0F prefix) */
	case 0x0F:
	{
		uint8_t opcode2 = read8(s);
		insn->opcode[1] = opcode2;
		insn->opcode_len = 2;

		switch (opcode2)
		{
		/* Long conditional jumps (Jcc rel32) */
		case 0x80: case 0x81: case 0x82: case 0x83:
		case 0x84: case 0x85: case 0x86: case 0x87:
		case 0x88: case 0x89: case 0x8A: case 0x8B:
		case 0x8C: case 0x8D: case 0x8E: case 0x8F:
			insn->type = INSN_Jcc;
			insn->cc = (enum x86_cc)(opcode2 & 0x0F);
			insn->num_ops = 1;
			insn->op[0].type = OP_REL;
			insn->op[0].size = opsz;
			insn->op[0].rel = (opsz == OPSZ_16) ? (int16_t)read16(s) : (int32_t)read32(s);
			break;

		/* SETcc r/m8 */
		case 0x90: case 0x91: case 0x92: case 0x93:
		case 0x94: case 0x95: case 0x96: case 0x97:
		case 0x98: case 0x99: case 0x9A: case 0x9B:
		case 0x9C: case 0x9D: case 0x9E: case 0x9F:
			insn->type = INSN_SETcc;
			insn->cc = (enum x86_cc)(opcode2 & 0x0F);
			insn->num_ops = 1;
			decode_modrm(s, insn, NULL, &insn->op[0], OPSZ_8);
			break;

		/* CMOVcc r, r/m */
		case 0x40: case 0x41: case 0x42: case 0x43:
		case 0x44: case 0x45: case 0x46: case 0x47:
		case 0x48: case 0x49: case 0x4A: case 0x4B:
		case 0x4C: case 0x4D: case 0x4E: case 0x4F:
			insn->type = INSN_CMOVcc;
			insn->cc = (enum x86_cc)(opcode2 & 0x0F);
			insn->num_ops = 2;
			decode_modrm(s, insn, &insn->op[0], &insn->op[1], opsz);
			break;

		/* MOVZX r, r/m8 / r/m16 */
		case 0xB6:
			insn->type = INSN_MOVZX;
			insn->num_ops = 2;
			decode_modrm(s, insn, &insn->op[0], &insn->op[1], OPSZ_8);
			insn->op[0].size = opsz;
			break;
		case 0xB7:
			insn->type = INSN_MOVZX;
			insn->num_ops = 2;
			decode_modrm(s, insn, &insn->op[0], &insn->op[1], OPSZ_16);
			insn->op[0].size = opsz;
			break;

		/* MOVSX r, r/m8 / r/m16 */
		case 0xBE:
			insn->type = INSN_MOVSX;
			insn->num_ops = 2;
			decode_modrm(s, insn, &insn->op[0], &insn->op[1], OPSZ_8);
			insn->op[0].size = opsz;
			break;
		case 0xBF:
			insn->type = INSN_MOVSX;
			insn->num_ops = 2;
			decode_modrm(s, insn, &insn->op[0], &insn->op[1], OPSZ_16);
			insn->op[0].size = opsz;
			break;

		/* IMUL r, r/m */
		case 0xAF:
			insn->type = INSN_IMUL2;
			insn->num_ops = 2;
			decode_modrm(s, insn, &insn->op[0], &insn->op[1], opsz);
			break;

		/* BSF/BSR */
		case 0xBC:
			insn->type = INSN_BSF;
			insn->num_ops = 2;
			decode_modrm(s, insn, &insn->op[0], &insn->op[1], opsz);
			break;
		case 0xBD:
			insn->type = INSN_BSR;
			insn->num_ops = 2;
			decode_modrm(s, insn, &insn->op[0], &insn->op[1], opsz);
			break;

		/* BT/BTS/BTR/BTC r/m, r */
		case 0xA3: insn->type = INSN_BT; goto bt_rm_r;
		case 0xAB: insn->type = INSN_BTS; goto bt_rm_r;
		case 0xB3: insn->type = INSN_BTR; goto bt_rm_r;
		case 0xBB: insn->type = INSN_BTC;
		bt_rm_r:
			insn->num_ops = 2;
			decode_modrm(s, insn, &insn->op[1], &insn->op[0], opsz);
			break;

		/* BT/BTS/BTR/BTC r/m, imm8 (Group 8) */
		case 0xBA:
		{
			decode_modrm(s, insn, NULL, &insn->op[0], opsz);
			int grp = (insn->modrm >> 3) & 7;
			switch (grp)
			{
			case 4: insn->type = INSN_BT; break;
			case 5: insn->type = INSN_BTS; break;
			case 6: insn->type = INSN_BTR; break;
			case 7: insn->type = INSN_BTC; break;
			default: insn->type = INSN_INVALID; break;
			}
			insn->num_ops = 2;
			insn->op[1].type = OP_IMM;
			insn->op[1].size = OPSZ_8;
			insn->op[1].imm = read8(s);
			break;
		}

		/* SHLD/SHRD r/m, r, imm8 / CL */
		case 0xA4:
			insn->type = INSN_SHLD;
			insn->num_ops = 3;
			decode_modrm(s, insn, &insn->op[1], &insn->op[0], opsz);
			insn->op[2].type = OP_IMM;
			insn->op[2].size = OPSZ_8;
			insn->op[2].imm = read8(s);
			break;
		case 0xA5:
			insn->type = INSN_SHLD;
			insn->num_ops = 3;
			decode_modrm(s, insn, &insn->op[1], &insn->op[0], opsz);
			insn->op[2].type = OP_REG;
			insn->op[2].reg = X86_REG_ECX;
			insn->op[2].size = OPSZ_8;
			break;
		case 0xAC:
			insn->type = INSN_SHRD;
			insn->num_ops = 3;
			decode_modrm(s, insn, &insn->op[1], &insn->op[0], opsz);
			insn->op[2].type = OP_IMM;
			insn->op[2].size = OPSZ_8;
			insn->op[2].imm = read8(s);
			break;
		case 0xAD:
			insn->type = INSN_SHRD;
			insn->num_ops = 3;
			decode_modrm(s, insn, &insn->op[1], &insn->op[0], opsz);
			insn->op[2].type = OP_REG;
			insn->op[2].reg = X86_REG_ECX;
			insn->op[2].size = OPSZ_8;
			break;

		/* XADD r/m, r */
		case 0xC0:
			insn->type = INSN_XADD;
			insn->num_ops = 2;
			decode_modrm(s, insn, &insn->op[1], &insn->op[0], OPSZ_8);
			break;
		case 0xC1:
			insn->type = INSN_XADD;
			insn->num_ops = 2;
			decode_modrm(s, insn, &insn->op[1], &insn->op[0], opsz);
			break;

		/* CMPXCHG r/m, r */
		case 0xB0:
			insn->type = INSN_CMPXCHG;
			insn->num_ops = 2;
			decode_modrm(s, insn, &insn->op[1], &insn->op[0], OPSZ_8);
			break;
		case 0xB1:
			insn->type = INSN_CMPXCHG;
			insn->num_ops = 2;
			decode_modrm(s, insn, &insn->op[1], &insn->op[0], opsz);
			break;

		/* BSWAP r32 */
		case 0xC8: case 0xC9: case 0xCA: case 0xCB:
		case 0xCC: case 0xCD: case 0xCE: case 0xCF:
			insn->type = INSN_BSWAP;
			insn->num_ops = 1;
			insn->op[0].type = OP_REG;
			insn->op[0].reg = opcode2 & 7;
			insn->op[0].size = OPSZ_32;
			break;

		/* CPUID */
		case 0xA2:
			insn->type = INSN_CPUID;
			insn->num_ops = 0;
			break;

		/* RDTSC */
		case 0x31:
			insn->type = INSN_RDTSC;
			insn->num_ops = 0;
			break;

		/* UD2 */
		case 0x0B:
			insn->type = INSN_UD2;
			insn->num_ops = 0;
			break;

		/* SYSENTER */
		case 0x34:
			insn->type = INSN_SYSENTER;
			insn->num_ops = 0;
			break;

		/* NOP r/m (0F 1F /0) - multi-byte NOP */
		case 0x1F:
			insn->type = INSN_NOP;
			decode_modrm(s, insn, NULL, &insn->op[0], opsz);
			insn->num_ops = 0;
			break;

		/* PUSH FS / POP FS / PUSH GS / POP GS */
		case 0xA0:
			insn->type = INSN_PUSH;
			insn->num_ops = 1;
			insn->op[0].type = OP_REG;
			insn->op[0].reg = X86_SEG_FS;
			insn->op[0].size = OPSZ_16;
			break;
		case 0xA1:
			insn->type = INSN_POP;
			insn->num_ops = 1;
			insn->op[0].type = OP_REG;
			insn->op[0].reg = X86_SEG_FS;
			insn->op[0].size = OPSZ_16;
			break;
		case 0xA8:
			insn->type = INSN_PUSH;
			insn->num_ops = 1;
			insn->op[0].type = OP_REG;
			insn->op[0].reg = X86_SEG_GS;
			insn->op[0].size = OPSZ_16;
			break;
		case 0xA9:
			insn->type = INSN_POP;
			insn->num_ops = 1;
			insn->op[0].type = OP_REG;
			insn->op[0].reg = X86_SEG_GS;
			insn->op[0].size = OPSZ_16;
			break;

		default:
			/* Unknown 2-byte opcode, treat as SSE or unknown */
			insn->type = INSN_SSE;
			insn->num_ops = 0;
			/* Skip ModR/M if present (many 0F opcodes have it) */
			if (s->pos < s->max_len)
			{
				decode_modrm(s, insn, NULL, &insn->op[0], opsz);
			}
			break;
		}
		break;
	}

	default:
		/* Unrecognized single-byte opcode */
		insn->type = INSN_INVALID;
		break;
	}

	insn->length = (uint8_t)s->pos;
	return s->pos;
}

static const char *insn_names[] = {
	[INSN_ADD] = "add", [INSN_OR] = "or", [INSN_ADC] = "adc", [INSN_SBB] = "sbb",
	[INSN_AND] = "and", [INSN_SUB] = "sub", [INSN_XOR] = "xor", [INSN_CMP] = "cmp",
	[INSN_INC] = "inc", [INSN_DEC] = "dec", [INSN_NEG] = "neg", [INSN_NOT] = "not",
	[INSN_MUL] = "mul", [INSN_IMUL] = "imul", [INSN_DIV] = "div", [INSN_IDIV] = "idiv",
	[INSN_IMUL2] = "imul", [INSN_IMUL3] = "imul",
	[INSN_ROL] = "rol", [INSN_ROR] = "ror", [INSN_RCL] = "rcl", [INSN_RCR] = "rcr",
	[INSN_SHL] = "shl", [INSN_SHR] = "shr", [INSN_SAR] = "sar",
	[INSN_SHLD] = "shld", [INSN_SHRD] = "shrd",
	[INSN_MOV] = "mov", [INSN_MOVZX] = "movzx", [INSN_MOVSX] = "movsx",
	[INSN_XCHG] = "xchg", [INSN_LEA] = "lea",
	[INSN_CBW] = "cbw", [INSN_CWD] = "cwd", [INSN_CDQ] = "cdq",
	[INSN_BSWAP] = "bswap", [INSN_CMOVcc] = "cmov",
	[INSN_PUSH] = "push", [INSN_POP] = "pop",
	[INSN_PUSHA] = "pusha", [INSN_POPA] = "popa",
	[INSN_PUSHF] = "pushf", [INSN_POPF] = "popf",
	[INSN_ENTER] = "enter", [INSN_LEAVE] = "leave",
	[INSN_JMP] = "jmp", [INSN_JMP_FAR] = "jmp far",
	[INSN_Jcc] = "jcc", [INSN_CALL] = "call", [INSN_CALL_FAR] = "call far",
	[INSN_RET] = "ret", [INSN_RET_FAR] = "retf",
	[INSN_LOOP] = "loop", [INSN_LOOPE] = "loope", [INSN_LOOPNE] = "loopne",
	[INSN_INT] = "int", [INSN_INT3] = "int3",
	[INSN_SYSENTER] = "sysenter", [INSN_IRET] = "iret",
	[INSN_MOVS] = "movs", [INSN_CMPS] = "cmps", [INSN_STOS] = "stos",
	[INSN_LODS] = "lods", [INSN_SCAS] = "scas",
	[INSN_BT] = "bt", [INSN_BTS] = "bts", [INSN_BTR] = "btr", [INSN_BTC] = "btc",
	[INSN_BSF] = "bsf", [INSN_BSR] = "bsr", [INSN_TEST] = "test",
	[INSN_SETcc] = "set", [INSN_STC] = "stc", [INSN_CLC] = "clc", [INSN_CMC] = "cmc",
	[INSN_STD] = "std", [INSN_CLD] = "cld", [INSN_STI] = "sti", [INSN_CLI] = "cli",
	[INSN_SAHF] = "sahf", [INSN_LAHF] = "lahf",
	[INSN_NOP] = "nop", [INSN_HLT] = "hlt", [INSN_CPUID] = "cpuid",
	[INSN_RDTSC] = "rdtsc", [INSN_UD2] = "ud2", [INSN_WAIT] = "wait",
	[INSN_MOV_SEG] = "mov seg", [INSN_FPU] = "fpu", [INSN_SSE] = "sse",
	[INSN_XADD] = "xadd", [INSN_CMPXCHG] = "cmpxchg", [INSN_CMPXCHG8B] = "cmpxchg8b",
};

const char *x86_insn_name(enum x86_insn_type type)
{
	if (type >= 0 && type < INSN_TYPE_COUNT)
		return insn_names[type] ? insn_names[type] : "???";
	return "INVALID";
}
