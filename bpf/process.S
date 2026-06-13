/* SPDX-License-Identifier: GPL-2.0 */

	.section "tracepoint/sched/sched_process_exit", "ax"
	.global trace_process_exit
trace_process_exit:
	r0 = 0
	exit

	.section "license", "a"
_license:
	.asciz "GPL"
