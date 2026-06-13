// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <linux/unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <elf.h>

#ifndef PERF_FLAG_FD_CLOEXEC
#define PERF_FLAG_FD_CLOEXEC	(1UL << 3)
#endif

#define ARRAY_SIZE(x)	(sizeof(x) / sizeof((x)[0]))
#define LOG_SIZE	65536

struct image {
	void *data;
	size_t len;
	Elf64_Ehdr *ehdr;
	Elf64_Shdr *shdrs;
	const char *shstr;
};

struct target {
	const char *obj;
	const char *sec;
	enum bpf_prog_type type;
	const char *event;
	const char *kgroup;
	int perf_fd;
	int prog_fd;
};

static struct target targets[] = {
	{ "bpf/syscall.o", "tracepoint/syscalls/sys_enter_execve",
	  BPF_PROG_TYPE_TRACEPOINT, "syscalls/sys_enter_execve", NULL, -1, -1 },
	{ "bpf/process.o", "tracepoint/sched/sched_process_exit",
	  BPF_PROG_TYPE_TRACEPOINT, "sched/sched_process_exit", NULL, -1, -1 },
	{ "bpf/net.o", "kprobe/tcp_connect",
	  BPF_PROG_TYPE_KPROBE, "tcp_connect", "asm_ebpf", -1, -1 },
};

static int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr)
{
	return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

static int sys_perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu,
			       int group_fd, unsigned long flags)
{
	return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static void close_fd(int *fd)
{
	if (*fd >= 0)
		close(*fd);
	*fd = -1;
}

static int read_file(const char *path, struct image *img)
{
	struct stat st;
	int fd;
	ssize_t n;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;

	if (fstat(fd, &st))
		goto err;
	if (st.st_size < (off_t)sizeof(Elf64_Ehdr)) {
		errno = ENOEXEC;
		goto err;
	}

	img->data = malloc(st.st_size);
	if (!img->data)
		goto err;

	img->len = st.st_size;
	n = read(fd, img->data, img->len);
	if (n != (ssize_t)img->len) {
		if (n >= 0)
			errno = EIO;
		goto err_data;
	}

	close(fd);
	return 0;

err_data:
	free(img->data);
	img->data = NULL;
err:
	close(fd);
	return -1;
}

static int parse_elf(struct image *img)
{
	Elf64_Shdr *shstr;
	unsigned char *ident;

	img->ehdr = img->data;
	ident = img->ehdr->e_ident;
	if (memcmp(ident, ELFMAG, SELFMAG) || ident[EI_CLASS] != ELFCLASS64 ||
	    ident[EI_DATA] != ELFDATA2LSB || img->ehdr->e_machine != EM_BPF) {
		errno = ENOEXEC;
		return -1;
	}

	if (!img->ehdr->e_shoff || img->ehdr->e_shentsize != sizeof(Elf64_Shdr) ||
	    img->ehdr->e_shstrndx == SHN_UNDEF) {
		errno = ENOEXEC;
		return -1;
	}

	if (img->ehdr->e_shoff + img->ehdr->e_shnum * sizeof(Elf64_Shdr) > img->len) {
		errno = ENOEXEC;
		return -1;
	}

	img->shdrs = (void *)((char *)img->data + img->ehdr->e_shoff);
	shstr = &img->shdrs[img->ehdr->e_shstrndx];
	if (shstr->sh_offset + shstr->sh_size > img->len) {
		errno = ENOEXEC;
		return -1;
	}

	img->shstr = (char *)img->data + shstr->sh_offset;
	return 0;
}

static Elf64_Shdr *find_section(struct image *img, const char *name)
{
	Elf64_Shdr *shdr;
	int i;

	for (i = 0; i < img->ehdr->e_shnum; i++) {
		shdr = &img->shdrs[i];
		if (!strcmp(img->shstr + shdr->sh_name, name))
			return shdr;
	}

	return NULL;
}

static int load_program(struct target *target)
{
	char log[LOG_SIZE];
	union bpf_attr attr;
	Elf64_Shdr *prog, *license;
	struct image img = { 0 };
	int fd;

	if (read_file(target->obj, &img))
		return -1;
	if (parse_elf(&img))
		goto err;

	prog = find_section(&img, target->sec);
	license = find_section(&img, "license");
	if (!prog || !license) {
		errno = ENOENT;
		goto err;
	}

	memset(&attr, 0, sizeof(attr));
	memset(log, 0, sizeof(log));
	attr.prog_type = target->type;
	attr.insn_cnt = prog->sh_size / sizeof(struct bpf_insn);
	attr.insns = (uint64_t)((char *)img.data + prog->sh_offset);
	attr.license = (uint64_t)((char *)img.data + license->sh_offset);
	attr.log_buf = (uint64_t)log;
	attr.log_size = sizeof(log);
	attr.log_level = 1;

	fd = sys_bpf(BPF_PROG_LOAD, &attr);
	if (fd < 0 && log[0])
		fprintf(stderr, "%s: verifier: %s\n", target->obj, log);
	if (fd < 0)
		goto err;

	target->prog_fd = fd;
	free(img.data);
	return 0;

err:
	free(img.data);
	return -1;
}

static int read_id_file(const char *path)
{
	char buf[32];
	int fd, id;
	ssize_t n;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return -1;
	buf[n] = '\0';
	id = atoi(buf);
	if (id <= 0) {
		errno = EINVAL;
		return -1;
	}

	return id;
}

static int attach_event(struct target *target, const char *event)
{
	char path[256];
	struct perf_event_attr attr;
	int id, fd;

	snprintf(path, sizeof(path),
		 "/sys/kernel/tracing/events/%s/id", event);
	id = read_id_file(path);
	if (id < 0) {
		snprintf(path, sizeof(path),
			 "/sys/kernel/debug/tracing/events/%s/id", event);
		id = read_id_file(path);
	}
	if (id < 0)
		return -1;

	memset(&attr, 0, sizeof(attr));
	attr.type = PERF_TYPE_TRACEPOINT;
	attr.size = sizeof(attr);
	attr.config = id;
	attr.sample_type = PERF_SAMPLE_RAW;
	attr.wakeup_events = 1;

	fd = sys_perf_event_open(&attr, -1, 0, -1, PERF_FLAG_FD_CLOEXEC);
	if (fd < 0)
		return -1;
	if (ioctl(fd, PERF_EVENT_IOC_SET_BPF, target->prog_fd)) {
		close(fd);
		return -1;
	}
	if (ioctl(fd, PERF_EVENT_IOC_ENABLE, 0)) {
		close(fd);
		return -1;
	}

	target->perf_fd = fd;
	return 0;
}

static int attach_tracepoint(struct target *target)
{
	return attach_event(target, target->event);
}

static int write_file(const char *path, const char *buf)
{
	int fd, ret;

	fd = open(path, O_WRONLY | O_CLOEXEC | O_APPEND);
	if (fd < 0)
		return -1;
	ret = write(fd, buf, strlen(buf));
	close(fd);
	return ret < 0 ? -1 : 0;
}

static int attach_kprobe(struct target *target)
{
	char event_path[128];
	char spec[256];

	snprintf(spec, sizeof(spec), "p:%s/%s %s\n",
		 target->kgroup, target->event, target->event);

	if (write_file("/sys/kernel/tracing/kprobe_events", spec) &&
	    write_file("/sys/kernel/debug/tracing/kprobe_events", spec))
		return -1;

	snprintf(event_path, sizeof(event_path), "%s/%s",
		 target->kgroup, target->event);
	return attach_event(target, event_path);
}

static int attach_program(struct target *target)
{
	if (target->type == BPF_PROG_TYPE_TRACEPOINT)
		return attach_tracepoint(target);
	if (target->type == BPF_PROG_TYPE_KPROBE)
		return attach_kprobe(target);
	errno = EINVAL;
	return -1;
}

static void detach_all(void)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(targets); i++) {
		close_fd(&targets[i].perf_fd);
		close_fd(&targets[i].prog_fd);
	}
}

int main(void)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(targets); i++) {
		if (load_program(&targets[i])) {
			perror(targets[i].obj);
			detach_all();
			return 1;
		}
		if (attach_program(&targets[i])) {
			perror(targets[i].sec);
			detach_all();
			return 1;
		}
		printf("attached %s\n", targets[i].sec);
	}

	pause();
	detach_all();
	return 0;
}
