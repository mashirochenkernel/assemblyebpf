/* SPDX-License-Identifier: GPL-2.0 */

	.include "bpf/event.inc"

	.section "tracepoint/syscalls/sys_enter_newfstatat", "ax"
	.global trace_newfstatat
trace_newfstatat:
	emit_str 12, 24

	.section "tracepoint/syscalls/sys_enter_unlinkat", "ax"
	.global trace_unlinkat
trace_unlinkat:
	emit_str 13, 24

	.section "tracepoint/syscalls/sys_enter_renameat2", "ax"
	.global trace_renameat2
trace_renameat2:
	emit_str 14, 24

	.section "tracepoint/syscalls/sys_enter_mkdirat", "ax"
	.global trace_mkdirat
trace_mkdirat:
	emit_str 15, 24

	.section "tracepoint/syscalls/sys_enter_rmdir", "ax"
	.global trace_rmdir
trace_rmdir:
	emit_str 16, 16

	.section "tracepoint/syscalls/sys_enter_fchmodat", "ax"
	.global trace_fchmodat
trace_fchmodat:
	emit_str 17, 24

	.section "tracepoint/syscalls/sys_enter_fchownat", "ax"
	.global trace_fchownat
trace_fchownat:
	emit_str 18, 24

	.section "license", "a"
_license:
	.asciz "GPL"
