/* SPDX-License-Identifier: GPL-2.0 */

	.include "bpf/event.inc"

	.section "tracepoint/sched/sched_process_exit", "ax"
	.global trace_process_exit
trace_process_exit:
	emit_exit 2

	.section "license", "a"
_license:
	.asciz "GPL"
