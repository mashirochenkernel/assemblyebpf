/* SPDX-License-Identifier: GPL-2.0 */

	.section "kprobe/tcp_connect", "ax"
	.global trace_tcp_connect
trace_tcp_connect:
	r0 = 0
	exit

	.section "license", "a"
_license:
	.asciz "GPL"
