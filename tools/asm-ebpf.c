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
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <elf.h>

#ifndef PERF_FLAG_FD_CLOEXEC
#define PERF_FLAG_FD_CLOEXEC	(1UL << 3)
#endif

#define ARRAY_SIZE(x)	(sizeof(x) / sizeof((x)[0]))
#define LOG_SIZE	65536
#define PERF_PAGES	8

struct event {
	uint32_t kind;
	uint32_t pad;
	uint64_t pid_tgid;
	char comm[16];
};

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

struct perf_reader {
	int fd;
	void *base;
	size_t len;
	uint64_t tail;
};

static struct target targets[] = {
	{ "bpf/syscall.o", "tracepoint/syscalls/sys_enter_execve",
	  BPF_PROG_TYPE_TRACEPOINT, "syscalls/sys_enter_execve", NULL, -1, -1 },
	{ "bpf/process.o", "tracepoint/sched/sched_process_exit",
	  BPF_PROG_TYPE_TRACEPOINT, "sched/sched_process_exit", NULL, -1, -1 },
	{ "bpf/file.o", "tracepoint/syscalls/sys_enter_openat",
	  BPF_PROG_TYPE_TRACEPOINT, "syscalls/sys_enter_openat", NULL, -1, -1 },
	{ "bpf/net.o", "kprobe/tcp_connect",
	  BPF_PROG_TYPE_KPROBE, "tcp_connect", "asm_ebpf", -1, -1 },
};

static int events_fd = -1;
static struct perf_reader *readers;
static int nr_readers;

static int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr)
{
	return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

static int create_perf_map(void)
{
	union bpf_attr attr;
	long ncpu;

	ncpu = sysconf(_SC_NPROCESSORS_CONF);
	if (ncpu <= 0)
		return -1;

	memset(&attr, 0, sizeof(attr));
	attr.map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY;
	attr.key_size = sizeof(uint32_t);
	attr.value_size = sizeof(uint32_t);
	attr.max_entries = ncpu;

	return sys_bpf(BPF_MAP_CREATE, &attr);
}

static int patch_perf_map(struct bpf_insn *insns, size_t cnt, int map_fd)
{
	size_t i;

	for (i = 0; i + 1 < cnt; i++) {
		if (insns[i].code == (BPF_LD | BPF_DW | BPF_IMM) &&
		    insns[i].dst_reg == BPF_REG_2 && !insns[i].src_reg &&
		    !insns[i].imm && !insns[i + 1].imm) {
			insns[i].src_reg = BPF_PSEUDO_MAP_FD;
			insns[i].imm = map_fd;
			return 0;
		}
	}

	errno = ENOENT;
	return -1;
}

static int sys_perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu,
			       int group_fd, unsigned long flags)
{
	return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static void die_errno(const char *what)
{
	int saved_errno = errno;

	perror(what);
	if (saved_errno == EPERM || saved_errno == EACCES) {
		fprintf(stderr, "run as root or grant BPF tracing capabilities\n");
		fprintf(stderr, "check kernel.unprivileged_bpf_disabled and perf_event_paranoid\n");
	}
}

static void close_fd(int *fd)
{
	if (*fd >= 0)
		close(*fd);
	*fd = -1;
}

static void close_readers(void)
{
	int i;

	for (i = 0; i < nr_readers; i++) {
		if (readers[i].base)
			munmap(readers[i].base, readers[i].len);
		close_fd(&readers[i].fd);
	}
	free(readers);
	readers = NULL;
	nr_readers = 0;
}

static int update_map_elem(int map_fd, uint32_t key, uint32_t value)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = map_fd;
	attr.key = (uint64_t)&key;
	attr.value = (uint64_t)&value;
	attr.flags = BPF_ANY;

	return sys_bpf(BPF_MAP_UPDATE_ELEM, &attr);
}

static int open_perf_readers(void)
{
	struct perf_event_attr attr;
	long page_size;
	int cpu;

	nr_readers = sysconf(_SC_NPROCESSORS_CONF);
	if (nr_readers <= 0)
		return -1;
	page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0)
		return -1;

	readers = calloc(nr_readers, sizeof(*readers));
	if (!readers)
		return -1;
	for (cpu = 0; cpu < nr_readers; cpu++)
		readers[cpu].fd = -1;

	for (cpu = 0; cpu < nr_readers; cpu++) {
		memset(&attr, 0, sizeof(attr));
		attr.type = PERF_TYPE_SOFTWARE;
		attr.size = sizeof(attr);
		attr.config = PERF_COUNT_SW_BPF_OUTPUT;
		attr.sample_type = PERF_SAMPLE_RAW;
		attr.wakeup_events = 1;

		readers[cpu].fd = sys_perf_event_open(&attr, -1, cpu, -1,
						       PERF_FLAG_FD_CLOEXEC);
		if (readers[cpu].fd < 0)
			goto err;

		readers[cpu].len = page_size * (PERF_PAGES + 1);
		readers[cpu].base = mmap(NULL, readers[cpu].len,
					      PROT_READ | PROT_WRITE, MAP_SHARED,
					      readers[cpu].fd, 0);
		if (readers[cpu].base == MAP_FAILED) {
			readers[cpu].base = NULL;
			goto err;
		}
		if (ioctl(readers[cpu].fd, PERF_EVENT_IOC_ENABLE, 0))
			goto err;
		if (update_map_elem(events_fd, cpu, readers[cpu].fd))
			goto err;
	}

	return 0;

err:
	close_readers();
	return -1;
}

static void print_event(const struct event *event)
{
	const char *kind = "unknown";

	if (event->kind == 1)
		kind = "exec";
	else if (event->kind == 2)
		kind = "exit";
	else if (event->kind == 3)
		kind = "tcp";
	else if (event->kind == 4)
		kind = "file";

	printf("%-5s pid=%llu tid=%llu comm=%.*s\n", kind,
	       (unsigned long long)(event->pid_tgid >> 32),
	       (unsigned long long)(event->pid_tgid & 0xffffffff),
	       (int)sizeof(event->comm), event->comm);
}

static void read_one(struct perf_reader *reader)
{
	struct perf_event_mmap_page *meta = reader->base;
	char *data = (char *)reader->base + sysconf(_SC_PAGESIZE);
	size_t data_size = reader->len - sysconf(_SC_PAGESIZE);
	uint64_t head = meta->data_head;

	__sync_synchronize();
	while (reader->tail < head) {
		struct perf_event_header *hdr;
		char buf[256];
		size_t offset, len, first;

		offset = reader->tail % data_size;
		first = data_size - offset;
		if (first >= sizeof(*hdr)) {
			hdr = (void *)(data + offset);
		} else {
			memcpy(buf, data + offset, first);
			memcpy(buf + first, data, sizeof(*hdr) - first);
			hdr = (void *)buf;
		}

		if (!hdr->size || hdr->size > sizeof(buf))
			break;

		len = hdr->size;
		if (first >= len) {
			memcpy(buf, data + offset, len);
		} else {
			memcpy(buf, data + offset, first);
			memcpy(buf + first, data, len - first);
		}

		if (hdr->type == PERF_RECORD_SAMPLE && len >= sizeof(*hdr) + 4) {
			uint32_t raw_len;

			memcpy(&raw_len, buf + sizeof(*hdr), sizeof(raw_len));
			if (raw_len >= sizeof(struct event) &&
			    sizeof(*hdr) + 4 + raw_len <= len)
				print_event((void *)(buf + sizeof(*hdr) + 4));
		}

		reader->tail += hdr->size;
	}
	meta->data_tail = reader->tail;
}

static int event_loop(void)
{
	struct pollfd *fds;
	int i;

	fds = calloc(nr_readers, sizeof(*fds));
	if (!fds)
		return -1;
	for (i = 0; i < nr_readers; i++) {
		fds[i].fd = readers[i].fd;
		fds[i].events = POLLIN;
	}

	for (;;) {
		if (poll(fds, nr_readers, -1) < 0) {
			if (errno == EINTR)
				break;
			free(fds);
			return -1;
		}
		for (i = 0; i < nr_readers; i++)
			if (fds[i].revents & POLLIN)
				read_one(&readers[i]);
	}

	free(fds);
	return 0;
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
	if (patch_perf_map((void *)((char *)img.data + prog->sh_offset),
			   attr.insn_cnt, events_fd))
		goto err;
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

static void remove_kprobe(struct target *target)
{
	char spec[128];

	if (!target->kgroup)
		return;
	snprintf(spec, sizeof(spec), "-:%s/%s\n", target->kgroup, target->event);
	write_file("/sys/kernel/tracing/kprobe_events", spec);
	write_file("/sys/kernel/debug/tracing/kprobe_events", spec);
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
		remove_kprobe(&targets[i]);
	}
	close_readers();
	close_fd(&events_fd);
}

int main(void)
{
	size_t i;
	int ret = 0;

	events_fd = create_perf_map();
	if (events_fd < 0) {
		die_errno("events map");
		return 1;
	}
	if (open_perf_readers()) {
		die_errno("perf readers");
		detach_all();
		return 1;
	}

	for (i = 0; i < ARRAY_SIZE(targets); i++) {
		if (load_program(&targets[i])) {
			die_errno(targets[i].obj);
			detach_all();
			return 1;
		}
		if (attach_program(&targets[i])) {
			die_errno(targets[i].sec);
			detach_all();
			return 1;
		}
		printf("attached %s\n", targets[i].sec);
	}

	ret = event_loop();
	if (ret)
		die_errno("poll");
	detach_all();
	return ret ? 1 : 0;
}
