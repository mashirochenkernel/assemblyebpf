/* SPDX-License-Identifier: GPL-2.0 */

	.include "bpf/event.inc"

	.section "tracepoint/syscalls/sys_enter_mmap", "ax"
	.global trace_mmap
trace_mmap:
	emit_aux 28, 24

	.section "tracepoint/syscalls/sys_enter_mprotect", "ax"
	.global trace_mprotect
trace_mprotect:
	emit_aux 29, 24

	.section "tracepoint/syscalls/sys_enter_munmap", "ax"
	.global trace_munmap
trace_munmap:
	emit_aux 30, 24

	.section "tracepoint/syscalls/sys_enter_brk", "ax"
	.global trace_brk
trace_brk:
	emit_aux 31, 16

	.section "license", "a"
_license:
	.asciz "GPL"
