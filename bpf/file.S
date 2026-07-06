/* SPDX-License-Identifier: GPL-2.0 */

	.include "bpf/event.inc"

	.section "tracepoint/syscalls/sys_enter_openat", "ax"
	.global trace_openat
trace_openat:
	enter_str_aux 4, 24, 32

	.section "tracepoint/syscalls/sys_exit_openat", "ax"
	.global trace_openat_exit
trace_openat_exit:
	emit_exit_fdpath

	.section "license", "a"
_license:
	.asciz "GPL"
