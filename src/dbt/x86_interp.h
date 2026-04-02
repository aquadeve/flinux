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
 * x86 Interpreter
 *
 * Pure software interpreter for x86 (32-bit) instructions.
 * This path works without executable memory allocation, making it
 * compatible with Xbox One retail mode (no JIT).
 *
 * Performance: ~20-50x slower than native execution, but adequate
 * for shell/bash usage on Xbox One.
 */

#pragma once

#include <dbt/x86_cpu.h>

/*
 * Execute instructions on the virtual CPU until an exit condition.
 *
 * @param cpu           The virtual x86 CPU state
 * @param max_insns     Maximum instructions to execute (0 = unlimited)
 *
 * @return Exit reason (syscall, fault, halt, etc.)
 */
enum x86_exit_reason x86_interp_run(struct x86_cpu *cpu, uint64_t max_insns);

/*
 * Execute a single instruction (for debugging/single-step).
 *
 * @param cpu   The virtual x86 CPU state
 * @return Exit reason
 */
enum x86_exit_reason x86_interp_step(struct x86_cpu *cpu);
