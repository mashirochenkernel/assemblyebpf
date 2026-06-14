/* SPDX-License-Identifier: GPL-2.0 */

	.include "bpf/event.inc"

	.section "tracepoint/syscalls/sys_enter_newfstatat", "ax"
	.global trace_newfstatat
trace_newfstatat:
	emit_event 12

	.section "tracepoint/syscalls/sys_enter_unlinkat", "ax"
	.global trace_unlinkat
trace_unlinkat:
	emit_event 13

	.section "tracepoint/syscalls/sys_enter_renameat2", "ax"
	.global trace_renameat2
trace_renameat2:
	emit_event 14

	.section "tracepoint/syscalls/sys_enter_mkdirat", "ax"
	.global trace_mkdirat
trace_mkdirat:
	emit_event 15

	.section "tracepoint/syscalls/sys_enter_rmdir", "ax"
	.global trace_rmdir
trace_rmdir:
	emit_event 16

	.section "tracepoint/syscalls/sys_enter_fchmodat", "ax"
	.global trace_fchmodat
trace_fchmodat:
	emit_event 17

	.section "tracepoint/syscalls/sys_enter_fchownat", "ax"
	.global trace_fchownat
trace_fchownat:
	emit_event 18

	.section "license", "a"
_license:
	.asciz "GPL"
