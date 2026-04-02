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
 * Dynamic Binary Translation - Main Implementation
 *
 * This is the heart of the x86-on-x64 translation layer. It manages
 * the virtual CPU, runs the interpreter loop, and bridges x86 Linux
 * syscalls to flinux's existing syscall translation layer.
 *
 * Architecture:
 * - Guest x86 binary executes via the interpreter (x86_interp)
 * - When INT 0x80 / SYSENTER is encountered, control returns here
 * - dbt_handle_syscall() reads the x86 register state and dispatches
 *   to the appropriate sys_*() handler from syscall_table_x86.h
 * - The syscall handler (already part of flinux) translates the Linux
 *   syscall into Windows API calls
 * - Return value is placed in guest EAX and execution resumes
 */

#include <dbt/dbt.h>
#include <dbt/x86_cpu.h>
#include <dbt/x86_interp.h>
#include <dbt/guest_memory.h>
#include <syscall/process.h>
#include <log.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <string.h>

/* The virtual x86 CPU */
static struct x86_cpu g_cpu;
static bool g_dbt_active = false;

/* ===== x86 syscall table (from Linux IA-32 ABI) ===== */
/*
 * We use the same syscall table defined in syscall_table_x86.h.
 * The dispatch is: EAX = syscall number, args in EBX, ECX, EDX, ESI, EDI, EBP.
 *
 * The existing flinux syscall handlers have this signature (for x86):
 *   int sys_XXX(int ebx, int ecx, int edx, int esi, int edi, int ebp, PCONTEXT context)
 *
 * In cross-arch mode, we don't have a real PCONTEXT, so we pass NULL
 * and the handlers that need it must be adapted.
 */

typedef int (*x86_syscall_fn)(int ebx, int ecx, int edx, int esi, int edi, int ebp, void *context);

#define SYSCALL(name) extern int sys_##name(int, int, int, int, int, int, void*);
#include <syscall/syscall_table_x86.h>
#undef SYSCALL

#define SYSCALL(name) (x86_syscall_fn)sys_##name,
static x86_syscall_fn x86_syscall_table[] = {
	(x86_syscall_fn)sys_unimplemented, /* syscall 0 (restart_syscall) */
#include <syscall/syscall_table_x86.h>
};
#undef SYSCALL

#define SYSCALL_COUNT_X86 (sizeof(x86_syscall_table) / sizeof(x86_syscall_table[0]))

/* Forward declaration */
extern void sys_unimplemented_imp(intptr_t id);

/* ===== Initialization ===== */

int dbt_init(void)
{
#ifdef _WIN64
	/* Only initialize DBT when running on x64 host for x86 guest */
	log_info("DBT: Initializing x86-on-x64 translation engine");

	if (guest_mem_init(0) < 0)
	{
		log_error("DBT: Failed to initialize guest memory");
		return -1;
	}

	x86_cpu_init(&g_cpu, guest_mem_base(), guest_mem_size());
	g_dbt_active = false; /* Will be set to true when dbt_run() is called */

	log_info("DBT: Initialization complete (interpreter mode)");
	return 0;
#else
	/* On native x86, no DBT needed */
	return 0;
#endif
}

void dbt_shutdown(void)
{
#ifdef _WIN64
	g_dbt_active = false;
	guest_mem_shutdown();
	log_info("DBT: Shutdown complete");
#endif
}

void dbt_reset(void)
{
#ifdef _WIN64
	x86_cpu_reset(&g_cpu);
	g_dbt_active = false;
	log_info("DBT: Reset complete");
#endif
}

bool dbt_is_active(void)
{
	return g_dbt_active;
}

uint32_t dbt_get_guest_eip(void)
{
	return g_cpu.eip;
}

/* ===== Syscall Bridge ===== */

/*
 * Handle a Linux x86 syscall.
 *
 * Linux IA-32 syscall convention:
 *   EAX = syscall number
 *   EBX = arg1, ECX = arg2, EDX = arg3
 *   ESI = arg4, EDI = arg5, EBP = arg6
 *   Return value in EAX
 */
int32_t dbt_handle_syscall(void)
{
	uint32_t nr = g_cpu.regs[X86_REG_EAX];
	int32_t ebx = (int32_t)g_cpu.regs[X86_REG_EBX];
	int32_t ecx = (int32_t)g_cpu.regs[X86_REG_ECX];
	int32_t edx = (int32_t)g_cpu.regs[X86_REG_EDX];
	int32_t esi = (int32_t)g_cpu.regs[X86_REG_ESI];
	int32_t edi = (int32_t)g_cpu.regs[X86_REG_EDI];
	int32_t ebp = (int32_t)g_cpu.regs[X86_REG_EBP];

	if (nr >= SYSCALL_COUNT_X86)
	{
		log_error("DBT: Invalid syscall number %u at EIP=%08x", nr, g_cpu.eip);
		return -1;
	}

	/*
	 * For pointers passed in syscall arguments, the guest passes 32-bit
	 * addresses. The flinux syscall handlers expect these as pointers.
	 * Since the guest memory is mapped at g_guest_base, we need to
	 * translate guest addresses to host addresses for pointer arguments.
	 *
	 * The existing handlers work with absolute pointers, so when a
	 * syscall argument is a pointer, we add g_guest_base to it.
	 *
	 * TODO: This is a simplification. A proper implementation would
	 * need per-syscall knowledge of which arguments are pointers.
	 * For now, the handlers receive the raw 32-bit values and the
	 * mm_check_read/write functions must be adapted for guest space.
	 */

	x86_syscall_fn handler = x86_syscall_table[nr];
	int32_t result = handler(ebx, ecx, edx, esi, edi, ebp, NULL);

	return result;
}

/* ===== Main Execution Loop ===== */

__declspec(noreturn) void dbt_run(uint32_t entrypoint, uint32_t stack_base, uint32_t stack_top)
{
	log_info("DBT: Starting execution at EIP=%08x ESP=%08x", entrypoint, stack_top);

	x86_cpu_set_entry(&g_cpu, entrypoint, stack_top);
	g_dbt_active = true;

	/* Main execution loop */
	while (1)
	{
		/* Run interpreter for a batch of instructions */
		enum x86_exit_reason reason = x86_interp_run(&g_cpu, 0 /* unlimited */);

		switch (reason)
		{
		case X86_EXIT_SYSCALL:
		{
			int32_t ret = dbt_handle_syscall();
			/* Place return value in EAX */
			g_cpu.regs[X86_REG_EAX] = (uint32_t)ret;
			break;
		}

		case X86_EXIT_HLT:
			log_info("DBT: Guest halted at EIP=%08x", g_cpu.eip);
			process_exit(0, 0);
			break;

		case X86_EXIT_FAULT:
			log_error("DBT: Guest fault at EIP=%08x", g_cpu.eip);
			log_error("DBT: EAX=%08x EBX=%08x ECX=%08x EDX=%08x",
				g_cpu.regs[X86_REG_EAX], g_cpu.regs[X86_REG_EBX],
				g_cpu.regs[X86_REG_ECX], g_cpu.regs[X86_REG_EDX]);
			log_error("DBT: ESI=%08x EDI=%08x EBP=%08x ESP=%08x",
				g_cpu.regs[X86_REG_ESI], g_cpu.regs[X86_REG_EDI],
				g_cpu.regs[X86_REG_EBP], g_cpu.regs[X86_REG_ESP]);
			process_exit(139, 0); /* SIGSEGV */
			break;

		case X86_EXIT_DIVZERO:
			log_error("DBT: Division by zero at EIP=%08x", g_cpu.eip);
			process_exit(136, 0); /* SIGFPE */
			break;

		case X86_EXIT_BREAKPOINT:
			log_info("DBT: Breakpoint at EIP=%08x", g_cpu.eip);
			/* Continue execution past the INT3 */
			break;

		case X86_EXIT_UNHANDLED:
			log_error("DBT: Unhandled instruction at EIP=%08x", g_cpu.eip);
			{
				uint8_t *code = x86_cpu_guest_to_host(&g_cpu, g_cpu.eip);
				log_error("DBT: Bytes: %02x %02x %02x %02x %02x %02x",
					code[0], code[1], code[2], code[3], code[4], code[5]);
			}
			process_exit(132, 0); /* SIGILL */
			break;

		default:
			log_error("DBT: Unknown exit reason %d", reason);
			process_exit(1, 0);
			break;
		}
	}
}
