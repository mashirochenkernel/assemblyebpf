/* SPDX-License-Identifier: GPL-2.0 */

	.include "bpf/event.inc"

	.section "tracepoint/syscalls/sys_enter_clone", "ax"
	.global trace_clone
trace_clone:
	emit_aux 19, 16

	.section "tracepoint/syscalls/sys_enter_clone3", "ax"
	.global trace_clone3
trace_clone3:
	emit_event 20

	.section "tracepoint/syscalls/sys_enter_fork", "ax"
	.global trace_fork
trace_fork:
	emit_event 21

	.section "tracepoint/syscalls/sys_enter_vfork", "ax"
	.global trace_vfork
trace_vfork:
	emit_event 22

	.section "tracepoint/syscalls/sys_enter_exit_group", "ax"
	.global trace_exit_group
trace_exit_group:
	emit_aux 23, 16

	.section "tracepoint/syscalls/sys_enter_kill", "ax"
	.global trace_kill
trace_kill:
	emit_aux 24, 24

	.section "tracepoint/syscalls/sys_enter_tkill", "ax"
	.global trace_tkill
trace_tkill:
	emit_aux 25, 24

	.section "tracepoint/syscalls/sys_enter_tgkill", "ax"
	.global trace_tgkill
trace_tgkill:
	emit_aux 26, 32

	.section "tracepoint/syscalls/sys_enter_prctl", "ax"
	.global trace_prctl
trace_prctl:
	emit_aux 27, 16

	.section "license", "a"
_license:
	.asciz "GPL"
