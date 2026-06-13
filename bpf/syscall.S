/* SPDX-License-Identifier: GPL-2.0 */

	.section "tracepoint/syscalls/sys_enter_execve", "ax"
	.global trace_execve
trace_execve:
	r0 = 0
	exit

	.section "license", "a"
_license:
	.asciz "GPL"
