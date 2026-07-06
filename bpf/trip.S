/* SPDX-License-Identifier: GPL-2.0 */

	.include "bpf/event.inc"

	.section "tracepoint/syscalls/sys_enter_openat", "ax"
	.global trip_openat
trip_openat:
	tripwire

	.section "license", "a"
_license:
	.asciz "GPL"
