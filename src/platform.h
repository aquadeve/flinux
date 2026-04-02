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

#pragma once

#ifdef _WIN64
#define Xip Rip
#define XWORD QWORD
#else
#define Xip Eip
#define XWORD DWORD
#endif

/*
 * FLINUX_DBT_X86_ON_X64: Defined when building the x64 host binary
 * that can run x86 (32-bit) Linux guest binaries via DBT.
 * This enables the cross-architecture ELF loader and interpreter.
 */
#if defined(_WIN64) && !defined(FLINUX_NATIVE_X64_ONLY)
#define FLINUX_DBT_X86_ON_X64 1
#endif
