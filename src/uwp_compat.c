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
 * UWP Compatibility Layer Implementation
 *
 * Provides UWP-safe replacements for Win32 APIs not available
 * in the Xbox One app container sandbox.
 */

#include <uwp_compat.h>
#include <log.h>

#include <stdbool.h>
#include <string.h>

/* Maximum path length for rootfs */
#define UWP_MAX_PATH 512

static bool g_uwp_initialized = false;
static bool g_is_app_container = false;
static bool g_jit_available = false;
static WCHAR g_rootfs_path[UWP_MAX_PATH];
static char g_command_line[4096];

/*
 * Detect if running in a UWP app container.
 * Uses GetCurrentPackageId which only succeeds in packaged apps.
 */
static bool detect_app_container(void)
{
	/*
	 * Try GetAppContainerNamedObjectPath to detect app container mode.
	 * This is already used by the existing flinux codebase.
	 */
	WCHAR obj_path[256];
	ULONG obj_path_len = sizeof(obj_path) / sizeof(WCHAR);
	BOOL result = GetAppContainerNamedObjectPath(NULL, NULL, obj_path_len, obj_path, &obj_path_len);
	return (result && obj_path_len > 0);
}

/*
 * Set up the rootfs path.
 * In UWP mode: use LocalState\rootfs within the app's data folder.
 * In desktop mode: use the legacy hardcoded path or current directory.
 */
static void setup_rootfs_path(void)
{
	if (g_is_app_container)
	{
		/*
		 * UWP apps can write to their LocalState folder.
		 * GetEnvironmentVariableW("LOCALAPPDATA") returns the app-specific
		 * local storage path in UWP.
		 *
		 * Alternatively, we can construct the path from the process token.
		 * For simplicity, use a well-known relative path that the UWP
		 * host app will set up before calling into flinux.
		 */
		DWORD len = GetEnvironmentVariableW(L"LOCALAPPDATA", g_rootfs_path, UWP_MAX_PATH - 16);
		if (len > 0 && len < UWP_MAX_PATH - 16)
		{
			wcscat_s(g_rootfs_path, UWP_MAX_PATH, L"\\rootfs");
		}
		else
		{
			/* Fallback: use a relative path */
			wcscpy_s(g_rootfs_path, UWP_MAX_PATH, L".\\rootfs");
		}
	}
	else
	{
		/* Desktop mode: use legacy path or current directory */
		DWORD len = GetCurrentDirectoryW(UWP_MAX_PATH, g_rootfs_path);
		if (len == 0)
		{
			wcscpy_s(g_rootfs_path, UWP_MAX_PATH, L"\\\\?\\C:\\Logs\\archlinux");
		}
	}
}

/*
 * Test JIT availability by trying to allocate executable memory.
 */
static void test_jit_capability(void)
{
	void *test = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);
	if (test)
	{
		VirtualFree(test, 0, MEM_RELEASE);
		g_jit_available = true;
	}
	else
	{
		g_jit_available = false;
	}
}

int uwp_compat_init(void)
{
	if (g_uwp_initialized)
		return 0;

	g_is_app_container = detect_app_container();
	setup_rootfs_path();
	test_jit_capability();

	/* Get command line */
	const char *cmdline = GetCommandLineA();
	if (cmdline)
	{
		strncpy_s(g_command_line, sizeof(g_command_line), cmdline, _TRUNCATE);
	}
	else
	{
		/* UWP fallback: provide default command line */
		strcpy_s(g_command_line, sizeof(g_command_line), "flinux /bin/bash");
	}

	g_uwp_initialized = true;

	log_info("UWP compat: app_container=%s jit=%s rootfs=%S",
		g_is_app_container ? "yes" : "no",
		g_jit_available ? "yes" : "no",
		g_rootfs_path);

	return 0;
}

WCHAR *uwp_get_rootfs_path(WCHAR *buf, int buf_size)
{
	if (!g_uwp_initialized)
		uwp_compat_init();

	if (buf && buf_size > 0)
	{
		wcscpy_s(buf, buf_size, g_rootfs_path);
		return buf;
	}
	return g_rootfs_path;
}

const char *uwp_get_command_line(void)
{
	if (!g_uwp_initialized)
		uwp_compat_init();
	return g_command_line;
}

bool uwp_is_app_container(void)
{
	return g_is_app_container;
}

bool uwp_jit_available(void)
{
	return g_jit_available;
}

__declspec(noreturn) void uwp_exit(int code)
{
	ExitProcess(code);
}
