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
 * Platform context for x64 host running x86 (32-bit) Linux guest binaries.
 * This provides the syscall_context structure used by the fork/process
 * subsystem when running in cross-architecture translation mode.
 */

#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

/*
 * syscall_context: Matches the x86/context.h layout so the existing
 * fork/process/signal code can work with translated x86 guest state.
 * All registers are 32-bit (the guest is 32-bit x86).
 */
struct syscall_context
{
	/* DO NOT REORDER */
	/* Context for fork() */
	DWORD ebx;
	DWORD ecx;
	DWORD edx;
	DWORD esi;
	DWORD edi;
	DWORD ebp;
	union
	{
		DWORD sp;
		DWORD esp;
	};
	union
	{
		DWORD pc;
		DWORD eip;
	};

	/* The following are not used by fork() */
	union
	{
		DWORD r0;
		DWORD eax;
	};
	DWORD eflags;
};
