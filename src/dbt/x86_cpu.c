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
 * x86 Virtual CPU Implementation
 *
 * Manages the virtual x86 processor state and guest memory access
 * for running 32-bit Linux binaries on an x64 host.
 */

#include <dbt/x86_cpu.h>
#include <log.h>

#include <string.h>

void x86_cpu_init(struct x86_cpu *cpu, uint8_t *guest_base, uint64_t guest_size)
{
	memset(cpu, 0, sizeof(*cpu));
	cpu->guest_base = guest_base;
	cpu->guest_size = guest_size;
	x86_cpu_reset(cpu);
}

void x86_cpu_reset(struct x86_cpu *cpu)
{
	/* Clear all general-purpose registers */
	memset(cpu->regs, 0, sizeof(cpu->regs));

	/* Initial EFLAGS: IF set, reserved bit 1 set */
	cpu->eflags = X86_IF | 0x2;

	/* Default segment selectors (Linux user mode) */
	cpu->segs[X86_SEG_CS] = 0x23;  /* User code segment */
	cpu->segs[X86_SEG_DS] = 0x2B;  /* User data segment */
	cpu->segs[X86_SEG_ES] = 0x2B;
	cpu->segs[X86_SEG_SS] = 0x2B;
	cpu->segs[X86_SEG_FS] = 0x00;  /* TLS - set later */
	cpu->segs[X86_SEG_GS] = 0x63;  /* TLS */

	/* Clear segment bases */
	memset(cpu->seg_base, 0, sizeof(cpu->seg_base));

	/* Initialize FPU to default state */
	memset(&cpu->fpu, 0, sizeof(cpu->fpu));
	cpu->fpu.fcw = 0x037F;   /* Default FPU control word */
	cpu->fpu.mxcsr = 0x1F80; /* Default MXCSR: all exceptions masked */
	cpu->fpu.mxcsr_mask = 0xFFFF;

	cpu->eip = 0;
	cpu->halted = false;
	cpu->exit_reason = X86_EXIT_UNHANDLED;
	cpu->insn_count = 0;
}

void x86_cpu_set_entry(struct x86_cpu *cpu, uint32_t eip, uint32_t esp)
{
	cpu->eip = eip;
	cpu->regs[X86_REG_ESP] = esp;
}

/*
 * Guest memory access functions.
 * All guest addresses are translated: host_ptr = guest_base + (guest_addr & mask)
 * This constrains the guest to a 4GB (or smaller) window within the host process.
 */

static inline uint8_t *guest_ptr(struct x86_cpu *cpu, uint32_t addr)
{
	return cpu->guest_base + addr;
}

uint8_t x86_cpu_read8(struct x86_cpu *cpu, uint32_t guest_addr)
{
	return *guest_ptr(cpu, guest_addr);
}

uint16_t x86_cpu_read16(struct x86_cpu *cpu, uint32_t guest_addr)
{
	uint16_t val;
	memcpy(&val, guest_ptr(cpu, guest_addr), sizeof(val));
	return val;
}

uint32_t x86_cpu_read32(struct x86_cpu *cpu, uint32_t guest_addr)
{
	uint32_t val;
	memcpy(&val, guest_ptr(cpu, guest_addr), sizeof(val));
	return val;
}

void x86_cpu_write8(struct x86_cpu *cpu, uint32_t guest_addr, uint8_t val)
{
	*guest_ptr(cpu, guest_addr) = val;
}

void x86_cpu_write16(struct x86_cpu *cpu, uint32_t guest_addr, uint16_t val)
{
	memcpy(guest_ptr(cpu, guest_addr), &val, sizeof(val));
}

void x86_cpu_write32(struct x86_cpu *cpu, uint32_t guest_addr, uint32_t val)
{
	memcpy(guest_ptr(cpu, guest_addr), &val, sizeof(val));
}

void x86_cpu_push32(struct x86_cpu *cpu, uint32_t val)
{
	cpu->regs[X86_REG_ESP] -= 4;
	x86_cpu_write32(cpu, cpu->regs[X86_REG_ESP], val);
}

uint32_t x86_cpu_pop32(struct x86_cpu *cpu)
{
	uint32_t val = x86_cpu_read32(cpu, cpu->regs[X86_REG_ESP]);
	cpu->regs[X86_REG_ESP] += 4;
	return val;
}

void *x86_cpu_guest_to_host(struct x86_cpu *cpu, uint32_t guest_addr)
{
	return (void *)guest_ptr(cpu, guest_addr);
}

uint32_t x86_cpu_host_to_guest(struct x86_cpu *cpu, void *host_ptr)
{
	uint8_t *p = (uint8_t *)host_ptr;
	if (p >= cpu->guest_base && p < cpu->guest_base + cpu->guest_size)
		return (uint32_t)(p - cpu->guest_base);
	return 0;
}
