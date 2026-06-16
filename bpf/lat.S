/* SPDX-License-Identifier: GPL-2.0 */

	.include "bpf/lat.inc"

	.section "tracepoint/syscalls/sys_enter_read", "ax"
	.global lat_read_enter
lat_read_enter:
	lat_enter

	.section "tracepoint/syscalls/sys_exit_read", "ax"
	.global lat_read_exit
lat_read_exit:
	lat_exit

	.section "license", "a"
_license:
	.asciz "GPL"
