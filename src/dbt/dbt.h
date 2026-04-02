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
 * Dynamic Binary Translation - Public API
 *
 * Provides the main entry points for running x86 Linux binaries
 * on an x64 Windows host. Includes initialization, execution loop,
 * and syscall bridge connecting the x86 guest to flinux's existing
 * Linux-to-Windows syscall translation layer.
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>

/*
 * Initialize the DBT subsystem.
 * Must be called before any other dbt_* functions.
 *
 * @return 0 on success, -1 on failure
 */
int dbt_init(void);

/*
 * Shut down the DBT subsystem and free all resources.
 */
void dbt_shutdown(void);

/*
 * Reset the DBT subsystem (for execve).
 */
void dbt_reset(void);

/*
 * Run an x86 binary from the given entry point with the given stack.
 * This is the main execution loop that replaces goto_entrypoint()
 * when running in cross-architecture mode.
 *
 * The function will:
 * 1. Initialize the virtual x86 CPU
 * 2. Set up the entry point and stack pointer
 * 3. Run the interpreter/JIT loop
 * 4. Handle syscalls by routing to flinux's syscall handlers
 * 5. Return only on process exit
 *
 * @param entrypoint  Guest entry point (32-bit EIP)
 * @param stack_base  Guest stack base address
 * @param stack_top   Guest stack top (initial ESP)
 */
__declspec(noreturn) void dbt_run(uint32_t entrypoint, uint32_t stack_base, uint32_t stack_top);

/*
 * Check if DBT mode is active (running x86 guest on x64 host).
 */
bool dbt_is_active(void);

/*
 * Get the current guest EIP (for debugging/logging).
 */
uint32_t dbt_get_guest_eip(void);

/*
 * Handle a Linux x86 syscall from the guest.
 * Called when the interpreter/JIT encounters INT 0x80 or SYSENTER.
 *
 * Reads syscall number and arguments from the guest CPU state
 * and dispatches to flinux's existing syscall handlers.
 *
 * @return Syscall return value (placed in guest EAX)
 */
int32_t dbt_handle_syscall(void);
