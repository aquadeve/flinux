/*
 * This file is part of Foreign Linux.
 *
 * FLinuxLib - UWP Static Library Implementation
 *
 * Provides the bridge between UWP host applications and the
 * Foreign Linux subsystem.
 */

#include "pch.h"
#include "FLinuxLib.h"

#include <string.h>

/* Terminal I/O callbacks from the UWP host */
static FLinux_WriteCallback g_write_callback = nullptr;
static FLinux_ReadCallback g_read_callback = nullptr;

/* Forward declarations of C functions */
extern "C" {
	extern void main(void);
	extern int uwp_compat_init(void);

#ifdef _WIN64
	extern int dbt_init(void);
	extern void dbt_shutdown(void);
	extern int dbt_is_active(void);
#endif
}

int FLinux_Init(const wchar_t *rootfs_path)
{
	uwp_compat_init();

	/*
	 * If a custom rootfs path is provided, override the UWP-detected one.
	 * The UWP host app can specify the rootfs location explicitly.
	 */
	if (rootfs_path)
	{
		wchar_t buf[512];
		wcsncpy_s(buf, sizeof(buf) / sizeof(buf[0]), rootfs_path, _TRUNCATE);
		/* Store for later use by vfs_init via uwp_get_rootfs_path */
		extern "C" void uwp_set_rootfs_path(const wchar_t *path);
		uwp_set_rootfs_path(rootfs_path);
	}

	return 0;
}

int FLinux_Run(const char *executable, int argc, const char **argv)
{
	/* Delegate to the main flinux entry point */
	/* The main() function handles initialization and execution */
	main();
	return 0;
}

void FLinux_Shutdown(void)
{
#ifdef _WIN64
	dbt_shutdown();
#endif
}

const char *FLinux_GetExecutionMode(void)
{
#ifdef _WIN64
	if (dbt_is_active())
		return "interpreter";
	return "native";
#else
	return "native";
#endif
}

void FLinux_SetTerminalCallbacks(FLinux_WriteCallback write_cb, FLinux_ReadCallback read_cb)
{
	g_write_callback = write_cb;
	g_read_callback = read_cb;
}

/*
 * Terminal I/O access functions for the flinux console subsystem.
 * These are called from C code in fs/console.c when running in UWP mode.
 */
extern "C" {

int uwp_terminal_write(const char *data, int len)
{
	if (g_write_callback)
	{
		g_write_callback(data, len);
		return len;
	}
	return -1;
}

int uwp_terminal_read(char *buf, int max_len)
{
	if (g_read_callback)
		return g_read_callback(buf, max_len);
	return -1;
}

} /* extern "C" */
