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
 * x86 JIT Compiler (Dev Mode only)
 *
 * Translates x86 basic blocks to native x64 code at runtime.
 * Requires PAGE_EXECUTE_READWRITE memory, which is only available
 * on Xbox One in Developer Mode. The interpreter is used as a
 * fallback when JIT is unavailable.
 *
 * Architecture:
 * - Decode x86 instructions using x86_decoder
 * - Emit equivalent x64 instructions into a translation cache
 * - Cache translated blocks keyed by guest EIP
 * - Chain blocks for hot paths
 */

#pragma once

#include <dbt/x86_cpu.h>
#include <stdbool.h>

/*
 * Translation cache entry: maps a guest EIP to translated x64 code.
 */
struct jit_block
{
	uint32_t guest_addr;      /* Guest start EIP */
	uint32_t guest_size;      /* Size of guest code in bytes */
	uint8_t *host_code;       /* Pointer to translated x64 code */
	uint32_t host_size;       /* Size of translated code in bytes */
	struct jit_block *next;   /* Hash chain */
};

/*
 * Initialize the JIT subsystem.
 * Tests whether executable memory allocation is possible.
 *
 * @return true if JIT is available, false if interpreter-only mode
 */
bool jit_init(void);

/*
 * Shut down the JIT subsystem and free translation cache.
 */
void jit_shutdown(void);

/*
 * Check if JIT mode is available and active.
 */
bool jit_is_available(void);

/*
 * Translate and execute starting from the current EIP.
 * Falls back to interpreter if JIT is unavailable.
 *
 * @param cpu   Virtual CPU state
 * @return Exit reason
 */
enum x86_exit_reason jit_execute(struct x86_cpu *cpu);

/*
 * Invalidate all cached translations (e.g., on self-modifying code).
 */
void jit_flush_cache(void);

/*
 * Invalidate translations for a specific guest address range.
 */
void jit_invalidate_range(uint32_t guest_addr, uint32_t size);
