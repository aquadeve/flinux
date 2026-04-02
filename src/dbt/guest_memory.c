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
 * Guest Memory Management Implementation
 *
 * Reserves a contiguous virtual address region in the x64 host to serve
 * as the guest's 32-bit address space. Uses VirtualAlloc/VirtualFree
 * for page-level management within the reserved region.
 */

#include <dbt/guest_memory.h>
#include <log.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

/* Global guest memory base pointer (exported for inline guest_to_host) */
uint8_t *g_guest_base = NULL;
static uint64_t g_guest_size = 0;

/*
 * Preferred base address for the guest address space.
 * We try to place it at a high address to avoid conflicts with
 * the host's own allocations. If this fails, VirtualAlloc will
 * choose a location.
 */
#define GUEST_PREFERRED_BASE ((void *)0x0000100000000000ULL)

int guest_mem_init(uint64_t requested_size)
{
	if (g_guest_base != NULL)
	{
		log_error("guest_mem_init: already initialized");
		return -1;
	}

	uint64_t size = requested_size ? requested_size : GUEST_MEM_DEFAULT_SIZE;

	/* Align to allocation granularity (64KB) */
	size = (size + GUEST_BLOCK_SIZE - 1) & ~((uint64_t)GUEST_BLOCK_SIZE - 1);

	/* Reserve (but don't commit) the full guest address space */
	g_guest_base = (uint8_t *)VirtualAlloc(
		GUEST_PREFERRED_BASE,
		(SIZE_T)size,
		MEM_RESERVE,
		PAGE_NOACCESS
	);

	if (!g_guest_base)
	{
		/* Try without preferred base */
		g_guest_base = (uint8_t *)VirtualAlloc(
			NULL,
			(SIZE_T)size,
			MEM_RESERVE,
			PAGE_NOACCESS
		);
	}

	if (!g_guest_base)
	{
		log_error("guest_mem_init: Failed to reserve %llu bytes", size);
		return -1;
	}

	g_guest_size = size;
	log_info("Guest memory: base=%p size=%llu MB", g_guest_base, size / (1024 * 1024));
	return 0;
}

void guest_mem_shutdown(void)
{
	if (g_guest_base)
	{
		VirtualFree(g_guest_base, 0, MEM_RELEASE);
		g_guest_base = NULL;
		g_guest_size = 0;
	}
}

uint8_t *guest_mem_base(void)
{
	return g_guest_base;
}

uint64_t guest_mem_size(void)
{
	return g_guest_size;
}

static DWORD prot_to_win32(int prot)
{
	/* prot uses Linux-style PROT_READ=1, PROT_WRITE=2, PROT_EXEC=4 */
	int r = prot & 1;
	int w = (prot >> 1) & 1;
	int x = (prot >> 2) & 1;

	if (x && w) return PAGE_EXECUTE_READWRITE;
	if (x && r) return PAGE_EXECUTE_READ;
	if (x)      return PAGE_EXECUTE;
	if (w)      return PAGE_READWRITE;
	if (r)      return PAGE_READONLY;
	return PAGE_NOACCESS;
}

uint32_t guest_mem_map(uint32_t guest_addr, uint32_t size, int prot, bool fixed)
{
	if (!g_guest_base)
		return 0;

	/* Align address down and size up to page boundaries */
	uint32_t aligned_addr = guest_addr & ~(GUEST_PAGE_SIZE - 1);
	uint32_t end = (guest_addr + size + GUEST_PAGE_SIZE - 1) & ~(GUEST_PAGE_SIZE - 1);
	uint32_t aligned_size = end - aligned_addr;

	if (aligned_addr + aligned_size > g_guest_size)
	{
		if (fixed)
			return 0;
		/* Find free space - simple linear scan */
		/* Start from a reasonable address (e.g., above program break area) */
		for (uint32_t addr = 0x10000000; addr + aligned_size <= g_guest_size; addr += GUEST_BLOCK_SIZE)
		{
			MEMORY_BASIC_INFORMATION mbi;
			if (VirtualQuery(g_guest_base + addr, &mbi, sizeof(mbi)))
			{
				if (mbi.State == MEM_RESERVE && mbi.RegionSize >= aligned_size)
				{
					aligned_addr = addr;
					goto do_commit;
				}
			}
		}
		return 0;
	}

do_commit:;
	void *host_addr = g_guest_base + aligned_addr;
	DWORD win_prot = prot_to_win32(prot);

	void *result = VirtualAlloc(host_addr, aligned_size, MEM_COMMIT, win_prot);
	if (!result)
	{
		log_error("guest_mem_map: VirtualAlloc failed at guest=%08x size=%u err=%u",
			aligned_addr, aligned_size, GetLastError());
		return 0;
	}

	return aligned_addr;
}

int guest_mem_unmap(uint32_t guest_addr, uint32_t size)
{
	if (!g_guest_base)
		return -1;

	uint32_t aligned_addr = guest_addr & ~(GUEST_PAGE_SIZE - 1);
	uint32_t end = (guest_addr + size + GUEST_PAGE_SIZE - 1) & ~(GUEST_PAGE_SIZE - 1);
	uint32_t aligned_size = end - aligned_addr;

	void *host_addr = g_guest_base + aligned_addr;

	/* Decommit (but keep reserved) */
	if (!VirtualFree(host_addr, aligned_size, MEM_DECOMMIT))
	{
		log_error("guest_mem_unmap: VirtualFree failed at guest=%08x", aligned_addr);
		return -1;
	}

	return 0;
}

int guest_mem_protect(uint32_t guest_addr, uint32_t size, int prot)
{
	if (!g_guest_base)
		return -1;

	uint32_t aligned_addr = guest_addr & ~(GUEST_PAGE_SIZE - 1);
	uint32_t end = (guest_addr + size + GUEST_PAGE_SIZE - 1) & ~(GUEST_PAGE_SIZE - 1);
	uint32_t aligned_size = end - aligned_addr;

	void *host_addr = g_guest_base + aligned_addr;
	DWORD old_prot;

	if (!VirtualProtect(host_addr, aligned_size, prot_to_win32(prot), &old_prot))
	{
		log_error("guest_mem_protect: VirtualProtect failed at guest=%08x", aligned_addr);
		return -1;
	}

	return 0;
}
