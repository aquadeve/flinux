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
 * x86 Virtual CPU State
 *
 * Represents the full state of a 32-bit x86 processor as seen by a Linux
 * guest binary. Used by both the interpreter and JIT translator.
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>

/* x86 general-purpose register indices */
#define X86_REG_EAX  0
#define X86_REG_ECX  1
#define X86_REG_EDX  2
#define X86_REG_EBX  3
#define X86_REG_ESP  4
#define X86_REG_EBP  5
#define X86_REG_ESI  6
#define X86_REG_EDI  7
#define X86_REG_COUNT 8

/* x86 segment register indices */
#define X86_SEG_ES   0
#define X86_SEG_CS   1
#define X86_SEG_SS   2
#define X86_SEG_DS   3
#define X86_SEG_FS   4
#define X86_SEG_GS   5
#define X86_SEG_COUNT 6

/* EFLAGS bit definitions */
#define X86_CF  (1 << 0)   /* Carry Flag */
#define X86_PF  (1 << 2)   /* Parity Flag */
#define X86_AF  (1 << 4)   /* Auxiliary Carry Flag */
#define X86_ZF  (1 << 6)   /* Zero Flag */
#define X86_SF  (1 << 7)   /* Sign Flag */
#define X86_TF  (1 << 8)   /* Trap Flag */
#define X86_IF  (1 << 9)   /* Interrupt Enable Flag */
#define X86_DF  (1 << 10)  /* Direction Flag */
#define X86_OF  (1 << 11)  /* Overflow Flag */
#define X86_IOPL_MASK (3 << 12)
#define X86_NT  (1 << 14)  /* Nested Task */
#define X86_RF  (1 << 16)  /* Resume Flag */
#define X86_VM  (1 << 17)  /* Virtual-8086 Mode */
#define X86_AC  (1 << 18)  /* Alignment Check */
#define X86_ID  (1 << 21)  /* CPUID Detection Flag */

/* x86 FPU state (FXSAVE/FXRSTOR format, 512 bytes) */
struct x86_fpu_state
{
	uint16_t fcw;           /* FPU Control Word */
	uint16_t fsw;           /* FPU Status Word */
	uint8_t  ftw;           /* Abridged FPU Tag Word */
	uint8_t  reserved1;
	uint16_t fop;           /* FPU Opcode */
	uint32_t fip;           /* FPU Instruction Pointer */
	uint16_t fcs;           /* FPU Code Segment */
	uint16_t reserved2;
	uint32_t fdp;           /* FPU Data Pointer */
	uint16_t fds;           /* FPU Data Segment */
	uint16_t reserved3;
	uint32_t mxcsr;         /* MXCSR Register */
	uint32_t mxcsr_mask;    /* MXCSR Mask */
	uint8_t  st_mm[8][16];  /* x87 FPU/MMX registers (ST0-ST7 / MM0-MM7) */
	uint8_t  xmm[8][16];   /* XMM registers 0-7 */
	uint8_t  reserved4[224]; /* Padding to 512 bytes */
};

/* Execution exit reasons */
enum x86_exit_reason
{
	X86_EXIT_SYSCALL,       /* int 0x80 or sysenter */
	X86_EXIT_HLT,           /* HLT instruction */
	X86_EXIT_FAULT,         /* Memory fault / segfault */
	X86_EXIT_DIVZERO,       /* Division by zero */
	X86_EXIT_BREAKPOINT,    /* INT3 breakpoint */
	X86_EXIT_UNHANDLED,     /* Unhandled instruction */
	X86_EXIT_SINGLE_STEP,   /* Single-step trap */
};

/*
 * Full x86 virtual CPU state.
 * This is the "virtual processor" that the DBT operates on.
 */
struct x86_cpu
{
	/* General-purpose registers, indexed by X86_REG_* */
	uint32_t regs[X86_REG_COUNT];

	/* Instruction pointer */
	uint32_t eip;

	/* Flags register */
	uint32_t eflags;

	/* Segment registers (selectors — not used for memory translation,
	 * but tracked for TLS and ABI compatibility) */
	uint16_t segs[X86_SEG_COUNT];

	/* Segment base addresses (for FS/GS based TLS) */
	uint32_t seg_base[X86_SEG_COUNT];

	/* FPU / SSE state */
	struct x86_fpu_state fpu __attribute__((aligned(16)));

	/* Exit reason after last execution quantum */
	enum x86_exit_reason exit_reason;

	/* Number of instructions executed in last quantum */
	uint64_t insn_count;

	/* Total instructions executed */
	uint64_t total_insn_count;

	/* Guest address space base (host pointer to start of 4GB guest region) */
	uint8_t *guest_base;

	/* Guest address space size (normally 0x100000000 = 4GB, but may be limited) */
	uint64_t guest_size;

	/* CPU is halted */
	bool halted;
};

/* Initialize a virtual CPU with default x86 state */
void x86_cpu_init(struct x86_cpu *cpu, uint8_t *guest_base, uint64_t guest_size);

/* Reset CPU to initial state (keeping memory mappings) */
void x86_cpu_reset(struct x86_cpu *cpu);

/* Set the entry point and initial stack pointer */
void x86_cpu_set_entry(struct x86_cpu *cpu, uint32_t eip, uint32_t esp);

/* Read a guest memory byte/word/dword through the CPU (with base translation) */
uint8_t  x86_cpu_read8(struct x86_cpu *cpu, uint32_t guest_addr);
uint16_t x86_cpu_read16(struct x86_cpu *cpu, uint32_t guest_addr);
uint32_t x86_cpu_read32(struct x86_cpu *cpu, uint32_t guest_addr);

/* Write to guest memory through the CPU */
void x86_cpu_write8(struct x86_cpu *cpu, uint32_t guest_addr, uint8_t val);
void x86_cpu_write16(struct x86_cpu *cpu, uint32_t guest_addr, uint16_t val);
void x86_cpu_write32(struct x86_cpu *cpu, uint32_t guest_addr, uint32_t val);

/* Push/pop 32-bit values on guest stack */
void x86_cpu_push32(struct x86_cpu *cpu, uint32_t val);
uint32_t x86_cpu_pop32(struct x86_cpu *cpu);

/* Get a host pointer for a guest address (for bulk read/write operations) */
void *x86_cpu_guest_to_host(struct x86_cpu *cpu, uint32_t guest_addr);

/* Convert host pointer back to guest address, returns 0 if not in guest space */
uint32_t x86_cpu_host_to_guest(struct x86_cpu *cpu, void *host_ptr);
