/* SPDX-License-Identifier: GPL-2.0 */

	.include "bpf/event.inc"

	.section "kprobe/tcp_close", "ax"
	.global trace_tcp_close
trace_tcp_close:
	emit_stack 32

	.section "kprobe/vfs_open", "ax"
	.global trace_vfs_open
trace_vfs_open:
	emit_stack 33

	.section "kprobe/vfs_unlink", "ax"
	.global trace_vfs_unlink
trace_vfs_unlink:
	emit_stack 34

	.section "kprobe/tcp_conn_request", "ax"
	.global trace_tcp_conn_request
trace_tcp_conn_request:
	emit_stack 35

	.section "license", "a"
_license:
	.asciz "GPL"
