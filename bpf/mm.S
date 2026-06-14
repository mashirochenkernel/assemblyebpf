/* SPDX-License-Identifier: GPL-2.0 */

	.include "bpf/event.inc"

	.section "tracepoint/syscalls/sys_enter_mmap", "ax"
	.global trace_mmap
trace_mmap:
	emit_event 28

	.section "tracepoint/syscalls/sys_enter_mprotect", "ax"
	.global trace_mprotect
trace_mprotect:
	emit_event 29

	.section "tracepoint/syscalls/sys_enter_munmap", "ax"
	.global trace_munmap
trace_munmap:
	emit_event 30

	.section "tracepoint/syscalls/sys_enter_brk", "ax"
	.global trace_brk
trace_brk:
	emit_event 31

	.section "license", "a"
_license:
	.asciz "GPL"
