/*
 * This file is part of Foreign Linux.
 *
 * FLinuxLib - UWP Static Library Interface
 *
 * Provides entry points for UWP host applications (including Xbox One)
 * to initialize and run the Foreign Linux subsystem with x86 binary
 * translation support.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Initialize the Foreign Linux subsystem.
 * Must be called before FLinux_Run().
 *
 * @param rootfs_path   Path to the Linux root filesystem (wide string).
 *                      If NULL, uses default UWP LocalState\rootfs path.
 * @return 0 on success, non-zero on failure
 */
int FLinux_Init(const wchar_t *rootfs_path);

/*
 * Run a Linux executable.
 *
 * @param executable    Linux executable path (e.g., "/bin/bash")
 * @param argc          Number of arguments
 * @param argv          Argument array
 * @return Exit code (normally does not return)
 */
int FLinux_Run(const char *executable, int argc, const char **argv);

/*
 * Shut down the Foreign Linux subsystem.
 */
void FLinux_Shutdown(void);

/*
 * Get the DBT (Dynamic Binary Translation) execution mode.
 *
 * @return "interpreter" if using software interpreter,
 *         "jit" if using JIT compilation,
 *         "native" if running same-architecture binaries
 */
const char *FLinux_GetExecutionMode(void);

/*
 * Terminal I/O callback type for UWP host apps.
 * The UWP host registers these callbacks to provide terminal I/O
 * since console APIs are not available on Xbox One.
 */
typedef void (*FLinux_WriteCallback)(const char *data, int len);
typedef int (*FLinux_ReadCallback)(char *buf, int max_len);

/*
 * Register terminal I/O callbacks.
 * Must be called before FLinux_Run() for terminal output to work.
 */
void FLinux_SetTerminalCallbacks(FLinux_WriteCallback write_cb, FLinux_ReadCallback read_cb);

#ifdef __cplusplus
}
#endif
