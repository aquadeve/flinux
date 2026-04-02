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
 * Decodes IA-32 (32-bit x86) instructions from a byte stream into a
 * structured representation suitable for interpretation or JIT translation.
 *
 * Handles the variable-length x86 encoding: prefixes, opcodes, ModR/M,
 * SIB, displacement, and immediate fields.
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>

/* Maximum instruction length in x86 */
#define X86_MAX_INSN_LEN 15

/* Prefix flags */
#define PREFIX_LOCK     (1 << 0)
#define PREFIX_REPNE    (1 << 1)   /* F2 */
#define PREFIX_REP      (1 << 2)   /* F3 (REP/REPE) */
#define PREFIX_SEG_ES   (1 << 3)
#define PREFIX_SEG_CS   (1 << 4)
#define PREFIX_SEG_SS   (1 << 5)
#define PREFIX_SEG_DS   (1 << 6)
#define PREFIX_SEG_FS   (1 << 7)
#define PREFIX_SEG_GS   (1 << 8)
#define PREFIX_OPSIZE   (1 << 9)   /* 66 - operand size override */
#define PREFIX_ADDRSIZE (1 << 10)  /* 67 - address size override */

/* Operand types */
enum x86_op_type
{
	OP_NONE,        /* No operand */
	OP_REG,         /* Register operand (from ModR/M reg or opcode) */
	OP_MEM,         /* Memory operand (from ModR/M r/m with mod != 3) */
	OP_IMM,         /* Immediate value */
	OP_REL,         /* Relative offset (for branches) */
};

/* Operand size */
enum x86_op_size
{
	OPSZ_8,
	OPSZ_16,
	OPSZ_32,
};

/* Memory addressing mode */
struct x86_mem_op
{
	int8_t base_reg;    /* Base register index, or -1 */
	int8_t index_reg;   /* Index register index, or -1 */
	uint8_t scale;      /* Scale factor (1, 2, 4, 8) */
	int32_t disp;       /* Displacement */
	uint8_t seg;        /* Segment override (X86_SEG_*), or 0xFF for default */
};

/* Decoded operand */
struct x86_operand
{
	enum x86_op_type type;
	enum x86_op_size size;
	union
	{
		uint8_t reg;                /* Register index for OP_REG */
		struct x86_mem_op mem;      /* Memory operand for OP_MEM */
		uint32_t imm;              /* Immediate value for OP_IMM */
		int32_t rel;               /* Relative offset for OP_REL */
	};
};

/* Instruction categories for the interpreter */
enum x86_insn_type
{
	/* Arithmetic */
	INSN_ADD, INSN_OR, INSN_ADC, INSN_SBB, INSN_AND, INSN_SUB, INSN_XOR, INSN_CMP,
	INSN_INC, INSN_DEC, INSN_NEG, INSN_NOT,
	INSN_MUL, INSN_IMUL, INSN_DIV, INSN_IDIV,
	INSN_IMUL2, INSN_IMUL3,  /* 2-operand and 3-operand IMUL */

	/* Shifts and rotates */
	INSN_ROL, INSN_ROR, INSN_RCL, INSN_RCR,
	INSN_SHL, INSN_SHR, INSN_SAR,
	INSN_SHLD, INSN_SHRD,

	/* Data transfer */
	INSN_MOV, INSN_MOVZX, INSN_MOVSX, INSN_XCHG,
	INSN_LEA,
	INSN_CBW, INSN_CWD, INSN_CDQ,
	INSN_BSWAP,
	INSN_CMOVcc,

	/* Stack */
	INSN_PUSH, INSN_POP,
	INSN_PUSHA, INSN_POPA,
	INSN_PUSHF, INSN_POPF,
	INSN_ENTER, INSN_LEAVE,

	/* Control flow */
	INSN_JMP, INSN_JMP_FAR,
	INSN_Jcc,       /* All conditional jumps */
	INSN_CALL, INSN_CALL_FAR,
	INSN_RET, INSN_RET_FAR,
	INSN_LOOP, INSN_LOOPE, INSN_LOOPNE,
	INSN_INT, INSN_INT3,
	INSN_SYSENTER,
	INSN_IRET,

	/* String operations */
	INSN_MOVS, INSN_CMPS, INSN_STOS, INSN_LODS, INSN_SCAS,

	/* Bit operations */
	INSN_BT, INSN_BTS, INSN_BTR, INSN_BTC,
	INSN_BSF, INSN_BSR,
	INSN_TEST,
	INSN_SETcc,

	/* Flags */
	INSN_STC, INSN_CLC, INSN_CMC,
	INSN_STD, INSN_CLD,
	INSN_STI, INSN_CLI,
	INSN_SAHF, INSN_LAHF,

	/* Misc */
	INSN_NOP,
	INSN_HLT,
	INSN_CPUID,
	INSN_RDTSC,
	INSN_UD2,
	INSN_WAIT,

	/* Segment / TLS */
	INSN_MOV_SEG,   /* mov sreg, r/m16 or mov r/m16, sreg */

	/* FPU (basic) */
	INSN_FPU,       /* Generic FPU instruction (decoded further by interpreter) */

	/* SSE (basic) */
	INSN_SSE,       /* Generic SSE instruction (decoded further by interpreter) */

	/* XADD, CMPXCHG */
	INSN_XADD, INSN_CMPXCHG, INSN_CMPXCHG8B,

	/* Total count */
	INSN_TYPE_COUNT,
	INSN_INVALID = -1,
};

/* Condition codes (used for Jcc, SETcc, CMOVcc) */
enum x86_cc
{
	CC_O = 0, CC_NO, CC_B, CC_NB, CC_Z, CC_NZ, CC_BE, CC_NBE,
	CC_S, CC_NS, CC_P, CC_NP, CC_L, CC_NL, CC_LE, CC_NLE,
};

/* Decoded instruction */
struct x86_insn
{
	enum x86_insn_type type;

	/* Prefix flags */
	uint32_t prefixes;

	/* Condition code (for Jcc, SETcc, CMOVcc) */
	enum x86_cc cc;

	/* Raw opcode bytes (1 or 2) */
	uint8_t opcode[2];
	uint8_t opcode_len;

	/* ModR/M and SIB (if present) */
	bool has_modrm;
	uint8_t modrm;
	uint8_t sib;

	/* Operands (up to 3) */
	struct x86_operand op[3];
	uint8_t num_ops;

	/* Operand size for this instruction (8, 16, or 32 bit) */
	enum x86_op_size op_size;

	/* Address size (16 or 32 bit) */
	enum x86_op_size addr_size;

	/* Total instruction length in bytes */
	uint8_t length;

	/* Address of instruction start (guest EIP) */
	uint32_t addr;

	/* FPU opcode for INSN_FPU */
	uint16_t fpu_opcode;
};

/*
 * Decode one x86 instruction.
 *
 * @param code      Pointer to instruction bytes (host memory)
 * @param max_len   Maximum number of bytes available
 * @param addr      Guest virtual address of the instruction
 * @param insn      Output: decoded instruction
 *
 * @return Number of bytes consumed, or 0 on decode failure
 */
int x86_decode(const uint8_t *code, int max_len, uint32_t addr, struct x86_insn *insn);

/*
 * Get a human-readable name for an instruction type.
 */
const char *x86_insn_name(enum x86_insn_type type);
