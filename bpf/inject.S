/* SPDX-License-Identifier: GPL-2.0 */

	.include "bpf/event.inc"

	.section "kprobe/__x64_sys_openat", "ax"
	.global inject_openat
inject_openat:
	inject

	.section "kprobe/__x64_sys_connect", "ax"
	.global inject_connect
inject_connect:
	inject

	.section "license", "a"
_license:
	.asciz "GPL"
