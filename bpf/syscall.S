/* SPDX-License-Identifier: GPL-2.0 */

	.include "bpf/event.inc"

	.section "tracepoint/syscalls/sys_enter_execve", "ax"
	.global trace_execve
trace_execve:
	emit_str 1, 16

	.section "license", "a"
_license:
	.asciz "GPL"
