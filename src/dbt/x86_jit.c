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
 * x86 JIT Compiler Implementation
 *
 * Provides JIT compilation of x86 basic blocks to x64 native code.
 * Only available when the OS allows executable memory allocation
 * (Desktop Windows or Xbox Dev Mode — NOT Xbox Retail).
 *
 * If JIT is unavailable, all execution falls back to the interpreter.
 *
 * TODO: This is a stub implementation. The actual x64 code generation
 * is planned for Phase 6 of the port. Currently all execution uses
 * the interpreter path.
 */

#include <dbt/x86_jit.h>
#include <dbt/x86_interp.h>
#include <log.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

/* Translation cache size (16 MB) */
#define JIT_CACHE_SIZE (16 * 1024 * 1024)

/* Hash table for block lookup */
#define JIT_HASH_SIZE 65536
#define JIT_HASH(addr) ((addr >> 2) & (JIT_HASH_SIZE - 1))

static bool g_jit_available = false;
static uint8_t *g_jit_cache = NULL;
static uint32_t g_jit_cache_used = 0;
static struct jit_block *g_jit_hash[JIT_HASH_SIZE];

bool jit_init(void)
{
	/* Test if we can allocate executable memory */
	void *test = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);
	if (!test)
	{
		log_info("JIT: Executable memory not available, using interpreter mode");
		g_jit_available = false;
		return false;
	}
	VirtualFree(test, 0, MEM_RELEASE);

	/* Allocate the translation cache */
	g_jit_cache = (uint8_t *)VirtualAlloc(NULL, JIT_CACHE_SIZE,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!g_jit_cache)
	{
		log_error("JIT: Failed to allocate translation cache");
		g_jit_available = false;
		return false;
	}

	g_jit_cache_used = 0;
	memset(g_jit_hash, 0, sizeof(g_jit_hash));
	g_jit_available = true;
	log_info("JIT: Translation cache allocated (%u MB)", JIT_CACHE_SIZE / (1024 * 1024));
	return true;
}

void jit_shutdown(void)
{
	if (g_jit_cache)
	{
		VirtualFree(g_jit_cache, 0, MEM_RELEASE);
		g_jit_cache = NULL;
	}
	g_jit_available = false;
	g_jit_cache_used = 0;
}

bool jit_is_available(void)
{
	return g_jit_available;
}

enum x86_exit_reason jit_execute(struct x86_cpu *cpu)
{
	/*
	 * TODO: Implement actual JIT compilation.
	 *
	 * For now, fall back to the interpreter.
	 * When implemented, this will:
	 * 1. Look up cpu->eip in the hash table
	 * 2. If found, execute the cached native code
	 * 3. If not found, translate the basic block at cpu->eip
	 * 4. Store in cache and execute
	 */
	return x86_interp_run(cpu, 0);
}

void jit_flush_cache(void)
{
	if (!g_jit_available)
		return;

	g_jit_cache_used = 0;
	memset(g_jit_hash, 0, sizeof(g_jit_hash));
	log_info("JIT: Cache flushed");
}

void jit_invalidate_range(uint32_t guest_addr, uint32_t size)
{
	if (!g_jit_available)
		return;

	/*
	 * TODO: Implement selective invalidation.
	 * For now, flush the entire cache on any invalidation.
	 */
	jit_flush_cache();
}
