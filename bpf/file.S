/* SPDX-License-Identifier: GPL-2.0 */

	.include "bpf/event.inc"

	.section "tracepoint/syscalls/sys_enter_openat", "ax"
	.global trace_openat
trace_openat:
	emit_str 4, 24

	.section "license", "a"
_license:
	.asciz "GPL"
