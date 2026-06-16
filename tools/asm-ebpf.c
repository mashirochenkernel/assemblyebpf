// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <linux/unistd.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <elf.h>

int tui_init(void);
void tui_fini(void);
int tui_winsize(unsigned short *rows, unsigned short *cols);
int tui_readkey(void);
void tui_render(const char *buf, unsigned long len);
unsigned long tui_u64(char *dst, unsigned long val);
unsigned long tui_human(char *dst, unsigned long val);

#ifndef PERF_FLAG_FD_CLOEXEC
#define PERF_FLAG_FD_CLOEXEC	(1UL << 3)
#endif

#define ARRAY_SIZE(x)	(sizeof(x) / sizeof((x)[0]))
#define LOG_SIZE	65536
#define PERF_PAGES	8
#define HIST_SLOTS	64
#define TP(obj, name) \
	{ obj, "tracepoint/" name, BPF_PROG_TYPE_TRACEPOINT, name, NULL, 1, NULL, NULL, 0 }
#define KP(obj, group, name) \
	{ obj, "kprobe/" name, BPF_PROG_TYPE_KPROBE, name, group, 1, NULL, NULL, 0 }
#define LAT(obj, name) \
	{ obj, "tracepoint/" name, BPF_PROG_TYPE_TRACEPOINT, name, NULL, 0, NULL, NULL, 0 }

struct event {
	uint32_t kind;
	uint32_t pad;
	uint64_t pid_tgid;
	uint64_t ts;
	uint64_t aux;
	char comm[16];
	char arg[128];
};

#define EVENT_HEAD	offsetof(struct event, arg)

struct filter {
	uint32_t pid;
	uint32_t have_comm;
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
	int head;
	int *perf_fds;
	int *prog_fds;
	int nr_fds;
};

struct perf_reader {
	int fd;
	void *base;
	size_t len;
	size_t data_offset;
	size_t data_size;
	uint64_t tail;
};

static struct target targets[] = {
	TP("bpf/syscall.o", "syscalls/sys_enter_execve"),
	TP("bpf/process.o", "sched/sched_process_exit"),
	TP("bpf/file.o", "syscalls/sys_enter_openat"),
	TP("bpf/io.o", "syscalls/sys_enter_read"),
	TP("bpf/io.o", "syscalls/sys_enter_write"),
	TP("bpf/io.o", "syscalls/sys_enter_close"),
	TP("bpf/socket.o", "syscalls/sys_enter_connect"),
	TP("bpf/socket.o", "syscalls/sys_enter_accept4"),
	TP("bpf/socket.o", "syscalls/sys_enter_sendto"),
	TP("bpf/socket.o", "syscalls/sys_enter_recvfrom"),
	TP("bpf/fs.o", "syscalls/sys_enter_newfstatat"),
	TP("bpf/fs.o", "syscalls/sys_enter_unlinkat"),
	TP("bpf/fs.o", "syscalls/sys_enter_renameat2"),
	TP("bpf/fs.o", "syscalls/sys_enter_mkdirat"),
	TP("bpf/fs.o", "syscalls/sys_enter_rmdir"),
	TP("bpf/fs.o", "syscalls/sys_enter_fchmodat"),
	TP("bpf/fs.o", "syscalls/sys_enter_fchownat"),
	TP("bpf/task.o", "syscalls/sys_enter_clone"),
	TP("bpf/task.o", "syscalls/sys_enter_clone3"),
	TP("bpf/task.o", "syscalls/sys_enter_fork"),
	TP("bpf/task.o", "syscalls/sys_enter_vfork"),
	TP("bpf/task.o", "syscalls/sys_enter_exit_group"),
	TP("bpf/task.o", "syscalls/sys_enter_kill"),
	TP("bpf/task.o", "syscalls/sys_enter_tkill"),
	TP("bpf/task.o", "syscalls/sys_enter_tgkill"),
	TP("bpf/task.o", "syscalls/sys_enter_prctl"),
	TP("bpf/mm.o", "syscalls/sys_enter_mmap"),
	TP("bpf/mm.o", "syscalls/sys_enter_mprotect"),
	TP("bpf/mm.o", "syscalls/sys_enter_munmap"),
	TP("bpf/mm.o", "syscalls/sys_enter_brk"),
	KP("bpf/net.o", "asm_ebpf", "tcp_connect"),
	KP("bpf/kprobe.o", "asm_ebpf", "tcp_close"),
	KP("bpf/kprobe.o", "asm_ebpf", "vfs_open"),
	KP("bpf/kprobe.o", "asm_ebpf", "vfs_unlink"),
	KP("bpf/kprobe.o", "asm_ebpf", "tcp_conn_request"),
	LAT("bpf/lat.o", "syscalls/sys_enter_read"),
	LAT("bpf/lat.o", "syscalls/sys_exit_read"),
};

static const struct evdesc {
	const char *name;
	const char *label;
} evdescs[] = {
	[1]  = { "exec",   NULL },
	[2]  = { "exit",   NULL },
	[3]  = { "tcp",    NULL },
	[4]  = { "open",   NULL },
	[5]  = { "read",   "fd" },
	[6]  = { "write",  "fd" },
	[7]  = { "close",  "fd" },
	[8]  = { "conn",   "fd" },
	[9]  = { "accept", "fd" },
	[10] = { "send",   "fd" },
	[11] = { "recv",   "fd" },
	[12] = { "stat",   NULL },
	[13] = { "unlink", NULL },
	[14] = { "rename", NULL },
	[15] = { "mkdir",  NULL },
	[16] = { "rmdir",  NULL },
	[17] = { "chmod",  NULL },
	[18] = { "chown",  NULL },
	[19] = { "clone",  "flags" },
	[20] = { "clone3", NULL },
	[21] = { "fork",   NULL },
	[22] = { "vfork",  NULL },
	[23] = { "exitg",  "code" },
	[24] = { "kill",   "sig" },
	[25] = { "tkill",  "sig" },
	[26] = { "tgkill", "sig" },
	[27] = { "prctl",  "opt" },
	[28] = { "mmap",   "len" },
	[29] = { "mprot",  "len" },
	[30] = { "munmap", "len" },
	[31] = { "brk",    "addr" },
	[32] = { "tcpclose", NULL },
	[33] = { "vfsopen",  NULL },
	[34] = { "vfsunlink", NULL },
	[35] = { "connreq", NULL },
};

static int events_fd = -1;
static int config_fd = -1;
static int count_fd = -1;
static int bytes_fd = -1;
static int start_fd = -1;
static int hist_fd = -1;
static int startlat_fd = -1;
static int pidstat_fd = -1;
static int self_pid;
static struct perf_reader *readers;
static int nr_readers;
static int reported_bad_sample;
static int reported_lost;
static int reported_record;
static volatile sig_atomic_t stop_flag;
static int tui_on;

static void on_signal(int sig)
{
	(void)sig;
	stop_flag = 1;
}

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

static int create_filter_map(void)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_type = BPF_MAP_TYPE_ARRAY;
	attr.key_size = sizeof(uint32_t);
	attr.value_size = sizeof(struct filter);
	attr.max_entries = 1;

	return sys_bpf(BPF_MAP_CREATE, &attr);
}

static int create_stat_map(void)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_type = BPF_MAP_TYPE_ARRAY;
	attr.key_size = sizeof(uint32_t);
	attr.value_size = sizeof(uint64_t);
	attr.max_entries = ARRAY_SIZE(evdescs);

	return sys_bpf(BPF_MAP_CREATE, &attr);
}

static int create_start_map(void)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_type = BPF_MAP_TYPE_HASH;
	attr.key_size = sizeof(uint32_t);
	attr.value_size = sizeof(uint64_t);
	attr.max_entries = 4096;

	return sys_bpf(BPF_MAP_CREATE, &attr);
}

static int create_hist_map(void)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_type = BPF_MAP_TYPE_ARRAY;
	attr.key_size = sizeof(uint32_t);
	attr.value_size = sizeof(uint64_t);
	attr.max_entries = HIST_SLOTS;

	return sys_bpf(BPF_MAP_CREATE, &attr);
}

static int create_startlat_map(void)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_type = BPF_MAP_TYPE_HASH;
	attr.key_size = sizeof(uint64_t);
	attr.value_size = sizeof(uint64_t);
	attr.max_entries = 4096;

	return sys_bpf(BPF_MAP_CREATE, &attr);
}

static int create_pidstat_map(void)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_type = BPF_MAP_TYPE_HASH;
	attr.key_size = sizeof(uint32_t);
	attr.value_size = sizeof(uint64_t);
	attr.max_entries = 16384;

	return sys_bpf(BPF_MAP_CREATE, &attr);
}

static int set_filter(int map_fd, const struct filter *filter)
{
	union bpf_attr attr;
	uint32_t key = 0;

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = map_fd;
	attr.key = (uint64_t)&key;
	attr.value = (uint64_t)filter;
	attr.flags = BPF_ANY;

	return sys_bpf(BPF_MAP_UPDATE_ELEM, &attr);
}

static int lookup_stat(int map_fd, uint32_t key, uint64_t *value)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = map_fd;
	attr.key = (uint64_t)&key;
	attr.value = (uint64_t)value;

	return sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr);
}

static int patch_map_fd(struct bpf_insn *insns, size_t cnt, int dst,
			int sentinel, int map_fd)
{
	size_t i;
	int found = 0;

	for (i = 0; i + 1 < cnt; i++) {
		if (insns[i].code == (BPF_LD | BPF_DW | BPF_IMM) &&
		    insns[i].dst_reg == dst && !insns[i].src_reg &&
		    insns[i].imm == sentinel && !insns[i + 1].imm) {
			insns[i].src_reg = BPF_PSEUDO_MAP_FD;
			insns[i].imm = map_fd;
			found = 1;
		}
	}

	if (found)
		return 0;

	errno = ENOENT;
	return -1;
}

static int patch_self_pid(struct bpf_insn *insns, size_t cnt, int pid)
{
	size_t i;

	for (i = 0; i < cnt; i++) {
		if (insns[i].code == (BPF_JMP | BPF_JNE | BPF_K) &&
		    insns[i].dst_reg == BPF_REG_1 && !insns[i].src_reg &&
		    !insns[i].imm) {
			insns[i].imm = pid;
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
		attr.sample_period = 1;
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
		readers[cpu].data_offset = page_size;
		readers[cpu].data_size = page_size * PERF_PAGES;
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

static uint64_t start_ts;

static void print_event(const struct event *event, int has_arg)
{
	const struct evdesc *desc = NULL;
	double rel;

	if (event->kind < ARRAY_SIZE(evdescs))
		desc = &evdescs[event->kind];

	if (!start_ts || event->ts < start_ts)
		start_ts = event->ts;
	rel = (event->ts - start_ts) / 1e9;

	printf("%-12.6f %-9s pid=%llu tid=%llu comm=%.*s", rel,
	       desc && desc->name ? desc->name : "unknown",
	       (unsigned long long)(event->pid_tgid >> 32),
	       (unsigned long long)(event->pid_tgid & 0xffffffff),
	       (int)sizeof(event->comm), event->comm);

	if (event->kind == 3) {
		uint32_t daddr = event->aux & 0xffffffff;
		uint16_t dport = (event->aux >> 32) & 0xffff;
		uint32_t saddr;
		uint16_t sport;
		const unsigned char *d = (const unsigned char *)&daddr;
		const unsigned char *s;

		memcpy(&saddr, event->arg, 4);
		memcpy(&sport, event->arg + 4, 2);
		s = (const unsigned char *)&saddr;
		printf(" %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u",
		       s[0], s[1], s[2], s[3], sport,
		       d[0], d[1], d[2], d[3], ntohs(dport));
	} else if (has_arg) {
		printf(" %.*s", (int)sizeof(event->arg), event->arg);
	} else if (event->kind == 2 && event->aux) {
		printf(" life=%.3fms", event->aux / 1e6);
	} else if (desc && desc->label) {
		printf(" %s=%llu", desc->label,
		       (unsigned long long)event->aux);
	}
	putchar('\n');
}

static void dump_counts(void)
{
	uint64_t total = 0;
	size_t i;

	fprintf(stderr, "\nevent counts\n");
	for (i = 0; i < ARRAY_SIZE(evdescs); i++) {
		uint64_t value, bytes = 0;

		if (!evdescs[i].name || lookup_stat(count_fd, i, &value))
			continue;
		lookup_stat(bytes_fd, i, &bytes);
		if (bytes)
			fprintf(stderr, "%-9s %llu req=%llu\n", evdescs[i].name,
				(unsigned long long)value,
				(unsigned long long)bytes);
		else
			fprintf(stderr, "%-9s %llu\n", evdescs[i].name,
				(unsigned long long)value);
		total += value;
	}
	fprintf(stderr, "total  %llu\n", (unsigned long long)total);
}

static void dump_hist(void)
{
	uint64_t slots[HIST_SLOTS] = { 0 };
	uint64_t max = 0;
	int i, hi = 0;

	for (i = 0; i < HIST_SLOTS; i++) {
		if (lookup_stat(hist_fd, i, &slots[i]))
			continue;
		if (slots[i]) {
			hi = i;
			if (slots[i] > max)
				max = slots[i];
		}
	}
	if (!max)
		return;

	fprintf(stderr, "\nread latency (ns)\n");
	for (i = 0; i <= hi; i++) {
		uint64_t lo = i ? 1ULL << i : 0;
		uint64_t up = i < 63 ? (1ULL << (i + 1)) - 1 : ~0ULL;
		int bar = (int)(slots[i] * 40 / max);
		int j;

		fprintf(stderr, "%12llu -> %-20llu |",
			(unsigned long long)lo, (unsigned long long)up);
		for (j = 0; j < bar; j++)
			putc('*', stderr);
		fprintf(stderr, " %llu\n", (unsigned long long)slots[i]);
	}
}

static int next_key(int map_fd, const uint32_t *key, uint32_t *next)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = map_fd;
	attr.key = (uint64_t)key;
	attr.next_key = (uint64_t)next;

	return sys_bpf(BPF_MAP_GET_NEXT_KEY, &attr);
}

static void dump_pidstat(void)
{
	uint32_t key = 0, next;
	uint32_t top_pid[10] = { 0 };
	uint64_t top_val[10] = { 0 };
	int have = 0, i, j;

	while (!next_key(pidstat_fd, have ? &key : NULL, &next)) {
		uint64_t value = 0;

		key = next;
		have = 1;
		if (lookup_stat(pidstat_fd, key, &value))
			continue;
		for (i = 0; i < 10; i++) {
			if (value > top_val[i]) {
				for (j = 9; j > i; j--) {
					top_val[j] = top_val[j - 1];
					top_pid[j] = top_pid[j - 1];
				}
				top_val[i] = value;
				top_pid[i] = key;
				break;
			}
		}
	}

	if (!top_val[0])
		return;
	fprintf(stderr, "\ntop pids by events\n");
	for (i = 0; i < 10 && top_val[i]; i++)
		fprintf(stderr, "pid=%-8u %llu\n", top_pid[i],
			(unsigned long long)top_val[i]);
}

static void read_one(struct perf_reader *reader)
{
	struct perf_event_mmap_page *meta = reader->base;
	size_t data_offset = meta->data_offset;
	size_t data_size = meta->data_size;
	char *data;
	uint64_t head = meta->data_head;

	if (!data_offset || !data_size) {
		data_offset = reader->data_offset;
		data_size = reader->data_size;
	}
	data = (char *)reader->base + data_offset;

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
			if (raw_len >= EVENT_HEAD &&
			    raw_len <= sizeof(struct event) &&
			    sizeof(*hdr) + 4 + raw_len <= len) {
				if (!tui_on)
					print_event((void *)(buf + sizeof(*hdr) + 4),
						    raw_len >= sizeof(struct event));
			} else if (!reported_bad_sample) {
				fprintf(stderr, "bad sample size %u record %zu\n",
					raw_len, len);
				reported_bad_sample = 1;
			}
		} else if (hdr->type == PERF_RECORD_LOST) {
			if (!reported_lost) {
				fprintf(stderr, "lost perf records\n");
				reported_lost = 1;
			}
		} else if (!reported_record) {
			fprintf(stderr, "perf record type %u size %u\n",
				hdr->type, hdr->size);
			reported_record = 1;
		}

		reader->tail += hdr->size;
	}
	meta->data_tail = reader->tail;
}

struct pidrow {
	uint32_t pid;
	uint64_t total;
	uint64_t rate;
};

static struct pidrow rows_cur[4096];
static struct pidrow rows_prev[4096];
static int nr_prev;

static int read_comm(uint32_t pid, char *buf, int len)
{
	char path[64];
	int fd;
	ssize_t n;

	snprintf(path, sizeof(path), "/proc/%u/comm", pid);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	n = read(fd, buf, len - 1);
	close(fd);
	if (n <= 0)
		return -1;
	if (buf[n - 1] == '\n')
		n--;
	buf[n] = '\0';
	return 0;
}

static uint64_t prev_total(uint32_t pid)
{
	int i;

	for (i = 0; i < nr_prev; i++)
		if (rows_prev[i].pid == pid)
			return rows_prev[i].total;
	return 0;
}

static int by_rate(const void *a, const void *b)
{
	const struct pidrow *x = a, *y = b;

	if (y->rate != x->rate)
		return y->rate > x->rate ? 1 : -1;
	return 0;
}

static int snapshot_pids(void)
{
	uint32_t key = 0, next;
	int have = 0, n = 0;

	while (n < (int)ARRAY_SIZE(rows_cur) &&
	       !next_key(pidstat_fd, have ? &key : NULL, &next)) {
		uint64_t value = 0;

		key = next;
		have = 1;
		if (lookup_stat(pidstat_fd, key, &value))
			continue;
		rows_cur[n].pid = key;
		rows_cur[n].total = value;
		rows_cur[n].rate = value - prev_total(key);
		n++;
	}
	return n;
}

static char *append(char *p, const char *s)
{
	while (*s)
		*p++ = *s++;
	return p;
}

static char *append_pad(char *p, const char *s, int width)
{
	int n = 0;

	while (*s && n < width) {
		*p++ = *s++;
		n++;
	}
	while (n < width) {
		*p++ = ' ';
		n++;
	}
	return p;
}

static void render_top(int rows, const char *filter)
{
	static char buf[65536];
	char comm[32];
	char *p = buf;
	int n, i, shown = 0, limit;

	n = snapshot_pids();
	qsort(rows_cur, n, sizeof(rows_cur[0]), by_rate);

	p = append(p, "\033[K asm-ebpf  top pids");
	if (filter[0]) {
		p = append(p, "  filter=");
		p = append(p, filter);
	}
	p = append(p, "   q:quit p:pause /:filter 1/2/3:view\r\n");
	p = append(p, "\033[K ");
	p = append_pad(p, "pid", 10);
	p = append_pad(p, "comm", 18);
	p = append_pad(p, "events", 12);
	p = append(p, "evt/s\r\n");

	limit = rows - 4;
	if (limit > 512)
		limit = 512;
	for (i = 0; i < n && shown < limit; i++) {
		char num[32];

		if (read_comm(rows_cur[i].pid, comm, sizeof(comm)))
			strcpy(comm, "?");
		if (filter[0] && !strstr(comm, filter))
			continue;
		p = append(p, "\033[K ");
		num[tui_u64(num, rows_cur[i].pid)] = '\0';
		p = append_pad(p, num, 10);
		p = append_pad(p, comm, 18);
		num[tui_u64(num, rows_cur[i].total)] = '\0';
		p = append_pad(p, num, 12);
		num[tui_u64(num, rows_cur[i].rate)] = '\0';
		p = append(p, num);
		p = append(p, "\r\n");
		shown++;
	}
	p = append(p, "\033[J");

	tui_render(buf, p - buf);

	memcpy(rows_prev, rows_cur, n * sizeof(rows_cur[0]));
	nr_prev = n;
}

static int tui_loop(void)
{
	struct pollfd *fds;
	char filter[32] = { 0 };
	int filt_mode = 0, paused = 0;
	unsigned short trows = 24, tcols = 80;
	int i;

	if (tui_init())
		return -1;

	fds = calloc(nr_readers + 1, sizeof(*fds));
	if (!fds) {
		tui_fini();
		return -1;
	}
	for (i = 0; i < nr_readers; i++) {
		fds[i].fd = readers[i].fd;
		fds[i].events = POLLIN;
	}
	fds[nr_readers].fd = 0;
	fds[nr_readers].events = POLLIN;

	(void)tcols;
	while (!stop_flag) {
		int key;

		if (poll(fds, nr_readers + 1, 500) < 0) {
			if (errno == EINTR)
				break;
			break;
		}
		for (i = 0; i < nr_readers; i++)
			read_one(&readers[i]);

		while ((key = tui_readkey()) >= 0) {
			if (filt_mode) {
				int l = strlen(filter);

				if (key == '\r' || key == '\n')
					filt_mode = 0;
				else if (key == 127 || key == 8) {
					if (l)
						filter[l - 1] = '\0';
				} else if (key == 27) {
					filt_mode = 0;
					filter[0] = '\0';
				} else if (l < (int)sizeof(filter) - 1) {
					filter[l] = key;
					filter[l + 1] = '\0';
				}
				continue;
			}
			if (key == 'q')
				stop_flag = 1;
			else if (key == 'p')
				paused = !paused;
			else if (key == '/')
				filt_mode = 1;
		}

		if (!paused) {
			tui_winsize(&trows, &tcols);
			if (trows < 6)
				trows = 6;
			render_top(trows, filter);
		}
	}

	tui_fini();
	free(fds);
	return 0;
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
		if (poll(fds, nr_readers, 1000) < 0) {
			if (errno == EINTR)
				break;
			free(fds);
			return -1;
		}
		for (i = 0; i < nr_readers; i++)
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
	struct bpf_insn *insns;
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
	insns = (void *)((char *)img.data + prog->sh_offset);
	if (patch_map_fd(insns, attr.insn_cnt, BPF_REG_2, 0, events_fd) &&
	    (target->head || errno != ENOENT))
		goto err;
	if (patch_self_pid(insns, attr.insn_cnt, self_pid) &&
	    (target->head || errno != ENOENT))
		goto err;
	if (patch_map_fd(insns, attr.insn_cnt, BPF_REG_1, 0, config_fd) &&
	    (target->head || errno != ENOENT))
		goto err;
	if (patch_map_fd(insns, attr.insn_cnt, BPF_REG_1, 1, count_fd) &&
	    (target->head || errno != ENOENT))
		goto err;
	if (patch_map_fd(insns, attr.insn_cnt, BPF_REG_1, 2, bytes_fd) &&
	    errno != ENOENT)
		goto err;
	if (patch_map_fd(insns, attr.insn_cnt, BPF_REG_1, 3, start_fd) &&
	    errno != ENOENT)
		goto err;
	if (patch_map_fd(insns, attr.insn_cnt, BPF_REG_1, 4, hist_fd) &&
	    errno != ENOENT)
		goto err;
	if (patch_map_fd(insns, attr.insn_cnt, BPF_REG_1, 5, startlat_fd) &&
	    errno != ENOENT)
		goto err;
	if (patch_map_fd(insns, attr.insn_cnt, BPF_REG_1, 6, pidstat_fd) &&
	    (target->head || errno != ENOENT))
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

	free(img.data);
	return fd;

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
	int cpu, err, id, ncpu, attached = 0;

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
	ncpu = sysconf(_SC_NPROCESSORS_CONF);
	if (ncpu <= 0)
		return -1;

	target->perf_fds = calloc(ncpu, sizeof(*target->perf_fds));
	target->prog_fds = calloc(ncpu, sizeof(*target->prog_fds));
	if (!target->perf_fds || !target->prog_fds) {
		free(target->perf_fds);
		free(target->prog_fds);
		target->perf_fds = NULL;
		target->prog_fds = NULL;
		return -1;
	}
	target->nr_fds = ncpu;
	for (cpu = 0; cpu < ncpu; cpu++) {
		target->perf_fds[cpu] = -1;
		target->prog_fds[cpu] = -1;
	}

	memset(&attr, 0, sizeof(attr));
	attr.type = PERF_TYPE_TRACEPOINT;
	attr.size = sizeof(attr);
	attr.config = id;
	attr.sample_type = PERF_SAMPLE_RAW;
	attr.wakeup_events = 1;

	for (cpu = 0; cpu < ncpu; cpu++) {
		target->prog_fds[cpu] = load_program(target);
		if (target->prog_fds[cpu] < 0)
			return -1;
		target->perf_fds[cpu] = sys_perf_event_open(&attr, -1, cpu, -1,
							PERF_FLAG_FD_CLOEXEC);
		if (target->perf_fds[cpu] < 0)
			return -1;
		if (ioctl(target->perf_fds[cpu], PERF_EVENT_IOC_SET_BPF,
			  target->prog_fds[cpu])) {
			err = errno;
			close_fd(&target->perf_fds[cpu]);
			close_fd(&target->prog_fds[cpu]);
			if (err == EEXIST) {
				fprintf(stderr, "skip %s cpu %d: already attached\n",
					target->sec, cpu);
				continue;
			}
			errno = err;
			return -1;
		}
		if (ioctl(target->perf_fds[cpu], PERF_EVENT_IOC_ENABLE, 0)) {
			err = errno;
			close_fd(&target->perf_fds[cpu]);
			close_fd(&target->prog_fds[cpu]);
			errno = err;
			return -1;
		}
		attached++;
	}

	if (!attached) {
		errno = EEXIST;
		return -1;
	}

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

static int selected(const char *sec, const char **sel, int nsel)
{
	int i;

	if (!nsel)
		return 1;
	for (i = 0; i < nsel; i++)
		if (strstr(sec, sel[i]))
			return 1;

	return 0;
}

static int can_skip(int err)
{
	return err == ENOENT || err == ENODEV || err == EINVAL ||
	       err == EOPNOTSUPP || err == ENOSYS || err == EEXIST;
}

static void close_target(struct target *target)
{
	int i;

	for (i = 0; i < target->nr_fds; i++)
		close_fd(&target->perf_fds[i]);
	for (i = 0; i < target->nr_fds; i++)
		close_fd(&target->prog_fds[i]);
	free(target->perf_fds);
	free(target->prog_fds);
	target->perf_fds = NULL;
	target->prog_fds = NULL;
	target->nr_fds = 0;
	remove_kprobe(target);
}

static void detach_all(void)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(targets); i++)
		close_target(&targets[i]);
	close_readers();
	close_fd(&events_fd);
	close_fd(&config_fd);
	close_fd(&count_fd);
	close_fd(&bytes_fd);
	close_fd(&start_fd);
	close_fd(&hist_fd);
	close_fd(&startlat_fd);
	close_fd(&pidstat_fd);
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s [-p pid] [-n comm] [--no-tui] [name ...]\n"
		"  -p pid    only events from this thread group\n"
		"  -n comm   only events from this command\n"
		"  --no-tui  stream events instead of the live view\n"
		"  name ...  attach only hooks whose section matches\n",
		prog);
}

int main(int argc, char **argv)
{
	struct filter filter;
	const char **sel;
	int nsel = 0;
	size_t i;
	int ret = 0;
	int attached = 0;
	int skipped = 0;
	int a;
	int no_tui = 0;

	memset(&filter, 0, sizeof(filter));
	sel = calloc(argc, sizeof(*sel));
	if (!sel)
		return 1;
	for (a = 1; a < argc; a++) {
		if (!strcmp(argv[a], "-h") || !strcmp(argv[a], "--help")) {
			usage(argv[0]);
			free(sel);
			return 0;
		} else if (!strcmp(argv[a], "--no-tui"))
			no_tui = 1;
		else if (!strcmp(argv[a], "-p") && a + 1 < argc)
			filter.pid = atoi(argv[++a]);
		else if (!strcmp(argv[a], "-n") && a + 1 < argc) {
			strncpy(filter.comm, argv[++a], sizeof(filter.comm) - 1);
			filter.have_comm = 1;
		} else
			sel[nsel++] = argv[a];
	}

	self_pid = getpid();
	tui_on = !no_tui && isatty(1);

	events_fd = create_perf_map();
	if (events_fd < 0) {
		die_errno("events map");
		free(sel);
		return 1;
	}
	config_fd = create_filter_map();
	if (config_fd < 0 || set_filter(config_fd, &filter)) {
		die_errno("filter map");
		detach_all();
		free(sel);
		return 1;
	}
	count_fd = create_stat_map();
	bytes_fd = create_stat_map();
	start_fd = create_start_map();
	hist_fd = create_hist_map();
	startlat_fd = create_startlat_map();
	pidstat_fd = create_pidstat_map();
	if (count_fd < 0 || bytes_fd < 0 || start_fd < 0 ||
	    hist_fd < 0 || startlat_fd < 0 || pidstat_fd < 0) {
		die_errno("stat map");
		detach_all();
		free(sel);
		return 1;
	}
	if (open_perf_readers()) {
		die_errno("perf readers");
		detach_all();
		free(sel);
		return 1;
	}

	for (i = 0; i < ARRAY_SIZE(targets); i++) {
		if (!selected(targets[i].sec, sel, nsel))
			continue;
		if (attach_program(&targets[i])) {
			if (can_skip(errno)) {
				fprintf(stderr, "skip %s: %s\n", targets[i].sec,
					strerror(errno));
				close_target(&targets[i]);
				skipped++;
				continue;
			}
			die_errno(targets[i].sec);
			detach_all();
			free(sel);
			return 1;
		}
		attached++;
		if (!tui_on)
			printf("attached %s\n", targets[i].sec);
	}
	free(sel);
	if (!attached) {
		fprintf(stderr, "no tracing programs attached\n");
		detach_all();
		return 1;
	}
	if (skipped)
		fprintf(stderr, "skipped %d unavailable hooks\n", skipped);

	if (tui_on) {
		struct sigaction sa = { 0 };

		sa.sa_handler = on_signal;
		sigaction(SIGINT, &sa, NULL);
		sigaction(SIGTERM, &sa, NULL);
		ret = tui_loop();
		if (ret)
			fprintf(stderr, "tui init failed; need a terminal\n");
	} else {
		ret = event_loop();
		if (ret)
			die_errno("poll");
		dump_counts();
		dump_hist();
		dump_pidstat();
	}
	detach_all();
	return ret ? 1 : 0;
}
