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
 * UWP Compatibility Layer
 *
 * Provides replacements and shims for Win32 APIs that are not available
 * in the Universal Windows Platform (UWP) app container, specifically
 * targeting Xbox One compatibility.
 *
 * Usage: Include this header and call uwp_compat_init() early in
 * application startup to set up UWP-safe paths and alternatives.
 */

#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <stdbool.h>

/*
 * Initialize UWP compatibility layer.
 * Sets up paths, detects capabilities, etc.
 *
 * @return 0 on success, -1 on failure
 */
int uwp_compat_init(void);

/*
 * Get the UWP-safe root filesystem path.
 * Returns the path to the rootfs directory within the app's local storage.
 * On non-UWP builds, returns the legacy hardcoded path.
 *
 * @param buf       Output buffer for the wide-string path
 * @param buf_size  Size of buffer in WCHARs
 * @return Pointer to buf on success, NULL on failure
 */
WCHAR *uwp_get_rootfs_path(WCHAR *buf, int buf_size);

/*
 * Get UWP-safe command line arguments.
 * On UWP, GetCommandLineA() may not be available or may return
 * unhelpful values. This provides the arguments passed to the app.
 *
 * @return Command line string (static buffer)
 */
const char *uwp_get_command_line(void);

/*
 * Check if we are running in a UWP app container.
 */
bool uwp_is_app_container(void);

/*
 * Check if JIT (executable memory allocation) is available.
 * Returns false on Xbox One retail mode.
 */
bool uwp_jit_available(void);

/*
 * UWP-safe process exit.
 */
__declspec(noreturn) void uwp_exit(int code);
