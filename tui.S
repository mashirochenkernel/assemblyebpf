/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Host-side terminal control for the asm-ebpf TUI, x86-64 System V ABI.
 * The eBPF programs stay under bpf; this file renders their maps.
 */

	.set	SYS_read, 0
	.set	SYS_write, 1
	.set	SYS_ioctl, 16

	.set	TCGETS, 0x5401
	.set	TCSETS, 0x5402
	.set	TIOCGWINSZ, 0x5413

	.set	ICANON, 0x2
	.set	ECHO, 0x8
	.set	ICRNL, 0x100
	.set	IXON, 0x400
	.set	VTIME_OFF, 22
	.set	VMIN_OFF, 23

	.bss
	.align	8
saved_termios:
	.skip	64
raw_termios:
	.skip	64

	.text

/* int tui_init(void): switch the terminal to raw mode, hide cursor. */
	.global	tui_init
tui_init:
	push	%rbx
	mov	$SYS_ioctl, %rax
	mov	$0, %rdi
	mov	$TCGETS, %rsi
	lea	saved_termios(%rip), %rdx
	syscall
	test	%rax, %rax
	js	1f

	lea	saved_termios(%rip), %rsi
	lea	raw_termios(%rip), %rdi
	mov	$8, %rcx
2:
	mov	(%rsi), %rax
	mov	%rax, (%rdi)
	add	$8, %rsi
	add	$8, %rdi
	dec	%rcx
	jnz	2b

	lea	raw_termios(%rip), %rdi
	mov	(%rdi), %eax
	and	$~(ICRNL | IXON), %eax
	mov	%eax, (%rdi)
	mov	12(%rdi), %eax
	and	$~(ICANON | ECHO), %eax
	mov	%eax, 12(%rdi)
	movb	$0, VMIN_OFF(%rdi)
	movb	$0, VTIME_OFF(%rdi)

	mov	$SYS_ioctl, %rax
	mov	$0, %rdi
	mov	$TCSETS, %rsi
	lea	raw_termios(%rip), %rdx
	syscall
	test	%rax, %rax
	js	1f

	lea	enter_seq(%rip), %rsi
	mov	$enter_len, %rdx
	call	write_stdout
	xor	%rax, %rax
	pop	%rbx
	ret
1:
	mov	$-1, %rax
	pop	%rbx
	ret

/* void tui_fini(void): restore the saved terminal mode, show cursor. */
	.global	tui_fini
tui_fini:
	push	%rbx
	lea	exit_seq(%rip), %rsi
	mov	$exit_len, %rdx
	call	write_stdout
	mov	$SYS_ioctl, %rax
	mov	$0, %rdi
	mov	$TCSETS, %rsi
	lea	saved_termios(%rip), %rdx
	syscall
	pop	%rbx
	ret

/* int tui_winsize(unsigned short *rows, unsigned short *cols). */
	.global	tui_winsize
tui_winsize:
	push	%rbx
	mov	%rdi, %rbx
	push	%r12
	mov	%rsi, %r12
	sub	$16, %rsp
	mov	$SYS_ioctl, %rax
	mov	$1, %rdi
	mov	$TIOCGWINSZ, %rsi
	mov	%rsp, %rdx
	syscall
	test	%rax, %rax
	js	3f
	mov	(%rsp), %ax
	mov	%ax, (%rbx)
	mov	2(%rsp), %ax
	mov	%ax, (%r12)
	xor	%rax, %rax
	jmp	4f
3:
	mov	$-1, %rax
4:
	add	$16, %rsp
	pop	%r12
	pop	%rbx
	ret

/* int tui_readkey(void): one byte from stdin, or -1 when none is ready. */
	.global	tui_readkey
tui_readkey:
	sub	$8, %rsp
	mov	$SYS_read, %rax
	mov	$0, %rdi
	mov	%rsp, %rsi
	mov	$1, %rdx
	syscall
	cmp	$1, %rax
	jne	5f
	movzbl	(%rsp), %eax
	add	$8, %rsp
	ret
5:
	mov	$-1, %rax
	add	$8, %rsp
	ret

/* internal: write(1, %rsi, %rdx) */
write_stdout:
	mov	$SYS_write, %rax
	mov	$1, %rdi
	syscall
	ret

/* void tui_render(const char *buf, unsigned long len): home cursor, blit. */
	.global	tui_render
tui_render:
	push	%rbx
	push	%r12
	sub	$8, %rsp
	mov	%rdi, %rbx
	mov	%rsi, %r12
	lea	home_seq(%rip), %rsi
	mov	$home_len, %rdx
	call	write_stdout
	mov	%rbx, %rsi
	mov	%r12, %rdx
	call	write_stdout
	add	$8, %rsp
	pop	%r12
	pop	%rbx
	ret

/*
 * unsigned long tui_u64(char *dst, unsigned long val):
 * write val in decimal at dst, return the digit count.
 */
	.global	tui_u64
tui_u64:
	mov	%rdi, %r8
	mov	%rsi, %rax
	mov	$10, %rcx
	sub	$40, %rsp
	lea	39(%rsp), %r9
	mov	%r9, %r10
1:
	xor	%rdx, %rdx
	div	%rcx
	add	$'0', %dl
	mov	%dl, (%r10)
	dec	%r10
	test	%rax, %rax
	jnz	1b

	inc	%r10
	mov	%r9, %rcx
	sub	%r10, %rcx
	inc	%rcx
	mov	%rcx, %r11
2:
	mov	(%r10), %al
	mov	%al, (%r8)
	inc	%r10
	inc	%r8
	dec	%rcx
	jnz	2b
	add	$40, %rsp
	mov	%r11, %rax
	ret

/*
 * unsigned long tui_human(char *dst, unsigned long val):
 * write val with a K/M/G/T suffix when large, return the byte count.
 */
	.global	tui_human
tui_human:
	push	%rbx
	push	%r12
	push	%r13
	mov	%rdi, %rbx
	mov	%rsi, %r12
	xor	%r13, %r13
	lea	suffixes(%rip), %rcx
3:
	cmp	$1024, %r12
	jb	4f
	cmp	$4, %r13
	je	4f
	xor	%rdx, %rdx
	mov	%r12, %rax
	mov	$1024, %r9
	div	%r9
	mov	%rax, %r12
	inc	%r13
	jmp	3b
4:
	mov	%rbx, %rdi
	mov	%r12, %rsi
	call	tui_u64
	add	%rax, %rbx
	test	%r13, %r13
	jz	5f
	lea	suffixes(%rip), %rcx
	movzbl	(%rcx, %r13), %edx
	mov	%dl, (%rbx)
	inc	%rbx
	inc	%rax
5:
	pop	%r13
	pop	%r12
	pop	%rbx
	ret

	.section .rodata
enter_seq:
	.ascii	"\033[?25l\033[2J\033[H"
	.set	enter_len, . - enter_seq
exit_seq:
	.ascii	"\033[?25h\033[2J\033[H"
	.set	exit_len, . - exit_seq
home_seq:
	.ascii	"\033[H"
	.set	home_len, . - home_seq
suffixes:
	.ascii	" KMGT"
