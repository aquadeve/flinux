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
 * Guest Memory Management
 *
 * Manages a reserved virtual address region in the x64 host process
 * that serves as the 32-bit guest's address space. All guest memory
 * operations (mmap, munmap, brk) operate within this region.
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>

/*
 * Default guest address space size.
 * On Xbox One, limit to 1GB to stay within UWP memory constraints.
 * On desktop Windows, can use up to 4GB.
 */
#ifdef FLINUX_XBOX
#define GUEST_MEM_DEFAULT_SIZE  (1ULL * 1024 * 1024 * 1024)  /* 1 GB */
#else
#define GUEST_MEM_DEFAULT_SIZE  (3ULL * 1024 * 1024 * 1024)  /* 3 GB */
#endif

#define GUEST_PAGE_SIZE  4096
#define GUEST_BLOCK_SIZE 65536

/*
 * Initialize the guest address space.
 * Reserves a contiguous region of host virtual memory.
 *
 * @param requested_size  Desired guest address space size (0 for default)
 * @return 0 on success, -1 on failure
 */
int guest_mem_init(uint64_t requested_size);

/*
 * Shut down and release the guest address space.
 */
void guest_mem_shutdown(void);

/*
 * Get the host base pointer of the guest address space.
 */
uint8_t *guest_mem_base(void);

/*
 * Get the size of the guest address space.
 */
uint64_t guest_mem_size(void);

/*
 * Map pages in the guest address space (equivalent to Linux mmap).
 *
 * @param guest_addr  Guest address (0 for auto-allocation)
 * @param size        Size in bytes
 * @param prot        Protection flags (PROT_READ | PROT_WRITE | PROT_EXEC)
 * @param fixed       If true, must map at exactly guest_addr
 *
 * @return Guest address of the mapping, or 0 on failure
 */
uint32_t guest_mem_map(uint32_t guest_addr, uint32_t size, int prot, bool fixed);

/*
 * Unmap pages in the guest address space.
 *
 * @param guest_addr  Guest address to unmap
 * @param size        Size in bytes
 * @return 0 on success, -1 on failure
 */
int guest_mem_unmap(uint32_t guest_addr, uint32_t size);

/*
 * Change protection of guest pages.
 *
 * @param guest_addr  Guest address
 * @param size        Size in bytes
 * @param prot        New protection flags
 * @return 0 on success, -1 on failure
 */
int guest_mem_protect(uint32_t guest_addr, uint32_t size, int prot);

/*
 * Convert guest address to host pointer.
 */
static inline void *guest_to_host(uint32_t guest_addr)
{
	extern uint8_t *g_guest_base;
	return g_guest_base + guest_addr;
}
