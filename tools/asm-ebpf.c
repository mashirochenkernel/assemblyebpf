// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
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
#include <time.h>
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
#define KP0(obj, group, name) \
	{ obj, "kprobe/" name, BPF_PROG_TYPE_KPROBE, name, group, 0, NULL, NULL, 0 }
#define LAT(obj, name) \
	{ obj, "tracepoint/" name, BPF_PROG_TYPE_TRACEPOINT, name, NULL, 0, NULL, NULL, 0 }

struct event {
	uint32_t kind;
	uint32_t stackid;
	uint64_t pid_tgid;
	uint64_t ts;
	uint64_t aux;
	int64_t ret;
	char comm[16];
	char arg[128];
};

#define EVENT_HEAD	offsetof(struct event, arg)

struct filter {
	uint32_t pid;
	uint32_t have_comm;
	char comm[16];
	uint64_t kinds;
	uint32_t inject_pid;
	uint32_t pad2;
	int64_t inject_ret;
	char trip_path[64];
	uint64_t peek_addr;
	uint32_t peek_pid;
	uint32_t pad3;
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
	LAT("bpf/file.o", "syscalls/sys_exit_openat"),
	TP("bpf/io.o", "syscalls/sys_enter_read"),
	TP("bpf/io.o", "syscalls/sys_enter_write"),
	TP("bpf/io.o", "syscalls/sys_enter_close"),
	TP("bpf/socket.o", "syscalls/sys_enter_connect"),
	LAT("bpf/socket.o", "syscalls/sys_exit_connect"),
	TP("bpf/socket.o", "syscalls/sys_enter_accept4"),
	LAT("bpf/socket.o", "syscalls/sys_exit_accept4"),
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
	KP0("bpf/inject.o", "asm_ebpf", "__x64_sys_openat"),
	KP0("bpf/inject.o", "asm_ebpf", "__x64_sys_connect"),
	LAT("bpf/trip.o", "syscalls/sys_enter_openat"),
	LAT("bpf/lat.o", "syscalls/sys_enter_read"),
	LAT("bpf/lat.o", "syscalls/sys_exit_read"),
	LAT("bpf/off.o", "sched/sched_switch"),
	LAT("bpf/peek.o", "raw_syscalls/sys_enter"),
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
	[36] = { "peek",   NULL },
};

static int events_fd = -1;
static int config_fd = -1;
static int count_fd = -1;
static int bytes_fd = -1;
static int start_fd = -1;
static int hist_fd = -1;
static int startlat_fd = -1;
static int pidstat_fd = -1;
static int pending_fd = -1;
static int fdpath_fd = -1;
static int stack_fd = -1;
static int offstart_fd = -1;
static int offcpu_fd = -1;
static int self_pid;

#define STACK_FRAMES	16
static struct perf_reader *readers;
static int nr_readers;
static int reported_bad_sample;
static int reported_lost;
static int reported_record;
static volatile sig_atomic_t stop_flag;
static int tui_on;
static int detail_mode;
static struct filter base_filter;

static void on_signal(int sig)
{
	(void)sig;
	stop_flag = 1;
}

static int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr)
{
	return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

struct ksym {
	uint64_t addr;
	char name[48];
};

static struct ksym *ksyms;
static int nksyms;

static void load_kallsyms(void)
{
	FILE *f = fopen("/proc/kallsyms", "r");
	char line[256];
	int cap = 1 << 17;

	if (!f)
		return;
	ksyms = malloc(cap * sizeof(*ksyms));
	if (!ksyms) {
		fclose(f);
		return;
	}
	while (fgets(line, sizeof(line), f)) {
		uint64_t addr;
		char type, name[64];

		if (sscanf(line, "%llx %c %63s", (unsigned long long *)&addr,
			   &type, name) != 3)
			continue;
		if (!addr || (type != 't' && type != 'T'))
			continue;
		if (nksyms == cap)
			break;
		ksyms[nksyms].addr = addr;
		snprintf(ksyms[nksyms].name, sizeof(ksyms[nksyms].name),
			 "%.47s", name);
		nksyms++;
	}
	fclose(f);
}

static int ksym_cmp(const void *a, const void *b)
{
	uint64_t x = ((const struct ksym *)a)->addr;
	uint64_t y = ((const struct ksym *)b)->addr;

	return x < y ? -1 : x > y ? 1 : 0;
}

static const char *sym_of(uint64_t addr)
{
	int lo = 0, hi = nksyms - 1, best = -1;

	while (lo <= hi) {
		int mid = (lo + hi) / 2;

		if (ksyms[mid].addr <= addr) {
			best = mid;
			lo = mid + 1;
		} else {
			hi = mid - 1;
		}
	}
	return best >= 0 ? ksyms[best].name : "?";
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

static int create_off_map(void)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_type = BPF_MAP_TYPE_HASH;
	attr.key_size = sizeof(uint32_t);
	attr.value_size = sizeof(uint64_t);
	attr.max_entries = 16384;

	return sys_bpf(BPF_MAP_CREATE, &attr);
}

static int create_pending_map(void)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_type = BPF_MAP_TYPE_HASH;
	attr.key_size = sizeof(uint64_t);
	attr.value_size = sizeof(struct event);
	attr.max_entries = 16384;

	return sys_bpf(BPF_MAP_CREATE, &attr);
}

static int create_fdpath_map(void)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_type = BPF_MAP_TYPE_HASH;
	attr.key_size = sizeof(uint64_t);
	attr.value_size = 128;
	attr.max_entries = 16384;

	return sys_bpf(BPF_MAP_CREATE, &attr);
}

static int create_stack_map(void)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_type = BPF_MAP_TYPE_STACK_TRACE;
	attr.key_size = sizeof(uint32_t);
	attr.value_size = STACK_FRAMES * sizeof(uint64_t);
	attr.max_entries = 8192;

	return sys_bpf(BPF_MAP_CREATE, &attr);
}

static int lookup_stack(uint32_t stackid, uint64_t *frames)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = stack_fd;
	attr.key = (uint64_t)&stackid;
	attr.value = (uint64_t)frames;

	return sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr);
}

static struct fdcache {
	uint64_t key;		/* 0 = empty */
	int found;
	char path[128];
} fdcache[512];

static void fdcache_clear(void)
{
	memset(fdcache, 0, sizeof(fdcache));
}

static int lookup_fdpath(uint64_t pid_tgid, uint64_t fd, char *out)
{
	union bpf_attr attr;
	uint64_t key = (pid_tgid & 0xffffffff00000000ULL) | (fd & 0xffffffff);
	unsigned h = (key ^ (key >> 32)) & (ARRAY_SIZE(fdcache) - 1);
	int ret;

	if (fdcache[h].key == key) {
		if (!fdcache[h].found)
			return -1;
		memcpy(out, fdcache[h].path, sizeof(fdcache[h].path));
		return 0;
	}

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = fdpath_fd;
	attr.key = (uint64_t)&key;
	attr.value = (uint64_t)out;
	ret = sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr);

	fdcache[h].key = key;
	fdcache[h].found = ret == 0;
	if (!ret)
		memcpy(fdcache[h].path, out, sizeof(fdcache[h].path));
	return ret;
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

static int has_ret(uint32_t kind)
{
	return kind == 4 || kind == 8 || kind == 9;
}

static void append_ret(char *out, int cap, const struct event *event)
{
	int len = strlen(out);

	if (cap - len < 8)
		return;
	if (event->ret < 0)
		snprintf(out + len, cap - len, " = -%s",
			 strerror((int)-event->ret));
	else
		snprintf(out + len, cap - len, " = %lld",
			 (long long)event->ret);
}

static int show_data = 1;

static int format_data(char *out, int cap, const char *data, int n)
{
	int len = 0, i;

	if (cap < 4)
		return 0;
	out[len++] = ' ';
	out[len++] = '"';
	for (i = 0; i < n && len < cap - 2; i++) {
		unsigned char c = data[i];

		if (c >= 0x20 && c < 0x7f)
			out[len++] = c;
		else if (c == '\n' && len < cap - 3) {
			out[len++] = '\\';
			out[len++] = 'n';
		} else
			out[len++] = '.';
	}
	out[len++] = '"';
	out[len] = '\0';
	return len;
}

static int has_stack(uint32_t kind)
{
	return kind == 3 || (kind >= 32 && kind <= 35);
}

static void append_stack(char *out, int cap, uint32_t stackid)
{
	uint64_t frames[STACK_FRAMES];
	int len = strlen(out), i, shown = 0;

	if (!nksyms || (int)stackid < 0 || lookup_stack(stackid, frames))
		return;
	for (i = 0; i < STACK_FRAMES && shown < 4 && frames[i]; i++) {
		const char *s = sym_of(frames[i]);

		if (len > cap - (int)strlen(s) - 4)
			break;
		len += snprintf(out + len, cap - len, "%s%s",
				shown ? "<-" : " [", s);
		shown++;
	}
	if (shown && len < cap - 1) {
		out[len++] = ']';
		out[len] = '\0';
	}
}

static int format_sockaddr(char *out, int cap, const char *sa)
{
	uint16_t family, port;

	memcpy(&family, sa, 2);
	memcpy(&port, sa + 2, 2);
	if (family == AF_INET) {
		const unsigned char *a = (const unsigned char *)(sa + 4);

		return snprintf(out, cap, " %u.%u.%u.%u:%u",
				a[0], a[1], a[2], a[3], ntohs(port));
	}
	if (family == AF_INET6) {
		char ip[INET6_ADDRSTRLEN];

		if (!inet_ntop(AF_INET6, sa + 8, ip, sizeof(ip)))
			strcpy(ip, "?");
		return snprintf(out, cap, " [%s]:%u", ip, ntohs(port));
	}
	return snprintf(out, cap, " af=%u", family);
}

static int format_argv(char *out, int cap, const char *arg)
{
	int i, w = 0;

	for (i = 0; i < 4 && w < cap - 1; i++) {
		const char *s = arg + i * 32;
		char slot[33];

		memcpy(slot, s, 32);
		slot[32] = '\0';
		if (!slot[0])
			break;
		w += snprintf(out + w, cap - w, "%s%s", i ? " " : " ", slot);
	}
	if (i == 4 && w < cap - 4)
		w += snprintf(out + w, cap - w, " ...");
	out[w < cap ? w : cap - 1] = '\0';
	return w;
}

struct execrec {
	uint32_t pid;
	uint64_t ts;
	char cmd[168];
};

#define EXEC_RING	128
static struct execrec exec_ring[EXEC_RING];
static unsigned exec_head;	/* monotonic count of execs recorded */

static void note_exec(const struct event *event)
{
	uint32_t pid = event->pid_tgid >> 32;
	char cmd[168];
	struct execrec *r;
	unsigned char *c;
	int back;

	format_argv(cmd, sizeof(cmd), event->arg);
	for (c = (unsigned char *)cmd; *c; c++)
		if (*c < 0x20 || *c >= 0x7f)	/* argv is untrusted: no
						   control or escape bytes into
						   the live view */
			*c = '.';

	/*
	 * A single execve is delivered once per per-cpu program copy, so the
	 * same command arrives in a tight burst.  Collapse identical pid+cmd
	 * within a short window; a genuine re-exec seconds later still shows.
	 */
	for (back = 1; back <= 32 && back <= (int)exec_head; back++) {
		struct execrec *q =
			&exec_ring[(exec_head - back) & (EXEC_RING - 1)];
		uint64_t dt = event->ts > q->ts ?
			      event->ts - q->ts : q->ts - event->ts;

		if (q->pid == pid && dt < 100000000ULL && !strcmp(q->cmd, cmd))
			return;
	}

	if (!start_ts || event->ts < start_ts)
		start_ts = event->ts;

	r = &exec_ring[exec_head & (EXEC_RING - 1)];
	r->pid = pid;
	r->ts = event->ts;
	memcpy(r->cmd, cmd, sizeof(r->cmd));
	exec_head++;
}

static uint64_t peek_addr;		/* armed user address, 0 = off */
static uint64_t peek_result_addr;
static unsigned char peek_data[64];
static int peek_have;
static int peek_mode;			/* typing an address */
static char peek_buf[24];

static void note_peek(const struct event *event)
{
	peek_result_addr = event->aux;
	memcpy(peek_data, event->arg, sizeof(peek_data));
	peek_have = 1;
}

static void print_event(const struct event *event, int has_arg)
{
	const struct evdesc *desc = NULL;
	char sabuf[64];
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
	} else if (event->kind == 8 || event->kind == 10) {
		format_sockaddr(sabuf, sizeof(sabuf), event->arg);
		printf("%s", sabuf);
	} else if (event->kind == 1 && has_arg) {
		char cmd[160];

		format_argv(cmd, sizeof(cmd), event->arg);
		printf("%s", cmd);
	} else if (has_arg) {
		printf(" %.*s", (int)sizeof(event->arg), event->arg);
		if (event->kind == 4)
			printf(" flags=0x%llx",
			       (unsigned long long)event->aux);
	} else if (event->kind == 2 && event->aux) {
		printf(" life=%.3fms", event->aux / 1e6);
	} else if (desc && desc->label) {
		printf(" %s=%llu", desc->label,
		       (unsigned long long)event->aux);
	}
	if (event->kind == 5 || event->kind == 6 || event->kind == 7) {
		char path[128];

		if (!lookup_fdpath(event->pid_tgid, event->aux, path) &&
		    path[0]) {
			path[sizeof(path) - 1] = '\0';
			printf(" %.100s", path);
		}
	}
	if (has_ret(event->kind)) {
		if (event->ret < 0)
			printf(" = -%s", strerror((int)-event->ret));
		else
			printf(" = %lld", (long long)event->ret);
	}
	if (has_stack(event->kind)) {
		char sb[256] = { 0 };

		append_stack(sb, sizeof(sb), event->stackid);
		printf("%s", sb);
	}
	putchar('\n');
}

/*
 * The detail view collapses repeated operations into one row with a counter,
 * so a thread that floods one syscall shows as a single growing line instead
 * of scrolling the rare, useful events off the screen.
 */
#define DETAIL_ROWS	64
#define DETAIL_TEXT	100

struct drow {
	char text[DETAIL_TEXT];
	uint64_t count;
	uint64_t seq;
};

static struct drow detail_rows[DETAIL_ROWS];
static uint64_t detail_seq;
static uint64_t detail_kind[ARRAY_SIZE(evdescs)];
static uint32_t detail_pid;

#define TK ARRAY_SIZE(evdescs)
static uint32_t trans[TK][TK];		/* prev-syscall -> next-syscall counts */
static int trans_prev = -1;
static uint64_t trans_last_ts;
static int show_matrix;			/* detail view: 'm' toggles fingerprint */

enum { KM_ALL, KM_NORW, KM_NETFILE, KM_COUNT };
static const char *km_name[KM_COUNT] = { "all", "no-rw", "net+file" };
static int detail_km;
static int inject_on;
static char trip_path[64];

static uint64_t km_mask(int m)
{
	static const int keep[] = { 1, 3, 4, 8, 9, 10, 11, 12, 13, 14,
				    15, 16, 17, 18 };
	uint64_t mask = 0;
	size_t i;

	if (m == KM_NORW) {
		for (i = 1; i < ARRAY_SIZE(evdescs); i++)
			if (evdescs[i].name)
				mask |= 1ULL << i;
		mask &= ~(1ULL << 5);
		mask &= ~(1ULL << 6);
	} else if (m == KM_NETFILE) {
		for (i = 0; i < ARRAY_SIZE(keep); i++)
			mask |= 1ULL << keep[i];
	}
	return mask;
}

static void detail_reset(uint32_t pid)
{
	detail_pid = pid;
	detail_seq = 0;
	fdcache_clear();
	memset(detail_rows, 0, sizeof(detail_rows));
	memset(detail_kind, 0, sizeof(detail_kind));
	memset(trans, 0, sizeof(trans));
	trans_prev = -1;
	trans_last_ts = 0;
}

static void event_summary(char *out, int cap, const struct event *event,
			  int has_arg)
{
	const struct evdesc *desc = NULL;
	int off;

	if (event->kind < ARRAY_SIZE(evdescs))
		desc = &evdescs[event->kind];

	off = snprintf(out, cap, "%-9s",
		       desc && desc->name ? desc->name : "unknown");
	if (off < 0 || off >= cap) {
		out[cap - 1] = '\0';
		return;
	}

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
		snprintf(out + off, cap - off,
			 " %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u",
			 s[0], s[1], s[2], s[3], sport,
			 d[0], d[1], d[2], d[3], ntohs(dport));
	} else if (event->kind == 8 || event->kind == 10) {
		format_sockaddr(out + off, cap - off, event->arg);
	} else if (event->kind == 1 && has_arg) {
		format_argv(out + off, cap - off, event->arg);
	} else if (has_arg) {
		int room = cap - off - 1;
		int n = snprintf(out + off, cap - off, " %.*s",
				 room < (int)sizeof(event->arg) ? room
							        : (int)sizeof(event->arg),
				 event->arg);

		if (event->kind == 4 && n > 0 && off + n < cap - 1)
			snprintf(out + off + n, cap - off - n, " flags=0x%llx",
				 (unsigned long long)event->aux);
	} else if (event->kind == 2 && event->aux) {
		snprintf(out + off, cap - off, " life=%.3fms",
			 event->aux / 1e6);
	} else if (desc && desc->label) {
		snprintf(out + off, cap - off, " %s=%llu", desc->label,
			 (unsigned long long)event->aux);
	}

	if (event->kind == 5 || event->kind == 6 || event->kind == 7) {
		char path[128];
		int len = strlen(out);

		if (!lookup_fdpath(event->pid_tgid, event->aux, path) &&
		    path[0] && len < cap - 4) {
			path[sizeof(path) - 1] = '\0';
			snprintf(out + len, cap - len, " %.*s",
				 cap - len - 2, path);
		}
	}
	if (event->kind == 6 && show_data) {
		int len = strlen(out);

		format_data(out + len, cap - len, event->arg, 48);
	}
	if (has_ret(event->kind))
		append_ret(out, cap, event);
	if (has_stack(event->kind))
		append_stack(out, cap, event->stackid);
}

static void detail_capture(const struct event *event, int has_arg)
{
	char text[DETAIL_TEXT];
	int i, slot = -1, oldest = -1;

	if ((uint32_t)(event->pid_tgid >> 32) != detail_pid)
		return;

	/*
	 * The same syscall is delivered once per per-cpu program copy and
	 * shares its nanosecond timestamp; distinct syscalls never do.  Count
	 * a behaviour transition only on the first delivery of each.
	 */
	if (event->ts != trans_last_ts) {
		int k = event->kind < TK ? (int)event->kind : (int)TK - 1;

		if (trans_prev >= 0)
			trans[trans_prev][k]++;
		trans_prev = k;
		trans_last_ts = event->ts;
	}

	if (event->kind < ARRAY_SIZE(evdescs))
		detail_kind[event->kind]++;

	event_summary(text, sizeof(text), event, has_arg);

	for (i = 0; i < DETAIL_ROWS; i++) {
		if (!detail_rows[i].count) {
			if (slot < 0)
				slot = i;
			continue;
		}
		if (oldest < 0 || detail_rows[i].seq < detail_rows[oldest].seq)
			oldest = i;
		if (!strcmp(detail_rows[i].text, text)) {
			detail_rows[i].count++;
			detail_rows[i].seq = ++detail_seq;
			return;
		}
	}

	if (slot < 0)
		slot = oldest;
	if (slot < 0)
		return;
	memcpy(detail_rows[slot].text, text, DETAIL_TEXT);
	detail_rows[slot].text[DETAIL_TEXT - 1] = '\0';
	detail_rows[slot].count = 1;
	detail_rows[slot].seq = ++detail_seq;
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
			    raw_len <= sizeof(struct event) + 7 &&
			    sizeof(*hdr) + 4 + raw_len <= len) {
				const struct event *ev =
					(void *)(buf + sizeof(*hdr) + 4);

				if (ev->kind == 1 &&
				    raw_len >= sizeof(struct event))
					note_exec(ev);
				if (ev->kind == 36)
					note_peek(ev);
				else if (detail_mode)
					detail_capture((void *)(buf + sizeof(*hdr) + 4),
						       raw_len >= sizeof(struct event));
				else if (!tui_on)
					print_event((void *)(buf + sizeof(*hdr) + 4),
						    raw_len >= sizeof(struct event));
			} else if (!reported_bad_sample && !tui_on) {
				fprintf(stderr, "bad sample size %u record %zu\n",
					raw_len, len);
				reported_bad_sample = 1;
			}
		} else if (hdr->type == PERF_RECORD_LOST) {
			if (!reported_lost && !tui_on) {
				fprintf(stderr, "lost perf records\n");
				reported_lost = 1;
			}
		} else if (!reported_record && !tui_on) {
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

static struct pidrow rows_cur[16384];
static struct pidrow rows_prev[16384];
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

static uint32_t read_ppid(uint32_t pid)
{
	char path[64], buf[256], *p;
	int fd;
	ssize_t n;

	snprintf(path, sizeof(path), "/proc/%u/stat", pid);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 0;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return 0;
	buf[n] = '\0';
	p = strrchr(buf, ')');		/* comm can hold spaces/parens */
	if (!p)
		return 0;
	p++;
	while (*p == ' ')
		p++;
	while (*p && *p != ' ')		/* skip state */
		p++;
	while (*p == ' ')
		p++;
	return (uint32_t)strtoul(p, NULL, 10);
}

/* open-addressed pid->total for the previous snapshot; pid 0 is empty */
#define PREVHASH	(1 << 15)
static struct {
	uint32_t pid;
	uint64_t total;
} prevhash[PREVHASH];

static void build_prevhash(void)
{
	int i;

	memset(prevhash, 0, sizeof(prevhash));
	for (i = 0; i < nr_prev; i++) {
		unsigned h = rows_prev[i].pid & (PREVHASH - 1);

		while (prevhash[h].pid)
			h = (h + 1) & (PREVHASH - 1);
		prevhash[h].pid = rows_prev[i].pid;
		prevhash[h].total = rows_prev[i].total;
	}
}

static uint64_t prev_total(uint32_t pid)
{
	unsigned h = pid & (PREVHASH - 1);

	while (prevhash[h].pid) {
		if (prevhash[h].pid == pid)
			return prevhash[h].total;
		h = (h + 1) & (PREVHASH - 1);
	}
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

	build_prevhash();
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

static char *append_u64(char *p, uint64_t v, int width)
{
	char num[24];

	num[tui_u64(num, v)] = '\0';
	if (width)
		return append_pad(p, num, width);
	return append(p, num);
}

struct win {
	int scroll;
	int visible;
	int ln;
	int total;
};

static char *win_line(char *p, struct win *w, const char *body)
{
	if (w->ln >= w->scroll && w->ln < w->scroll + w->visible) {
		p = append(p, "\033[K");
		p = append(p, body);
		p = append(p, "\r\n");
	}
	w->ln++;
	w->total++;
	return p;
}

static void win_clamp(struct win *w, int *scroll)
{
	if (*scroll > w->total - w->visible)
		*scroll = w->total - w->visible;
	if (*scroll < 0)
		*scroll = 0;
}

static char *win_footer(char *p, struct win *w)
{
	char n[24];

	if (w->total > w->visible || w->scroll) {
		p = append(p, "\033[K -- ");
		n[tui_u64(n, w->scroll + 1)] = '\0';
		p = append(p, n);
		p = append(p, "..");
		n[tui_u64(n, w->scroll + w->visible < w->total ?
			  w->scroll + w->visible : w->total)] = '\0';
		p = append(p, n);
		p = append(p, "/");
		n[tui_u64(n, w->total)] = '\0';
		p = append(p, n);
		p = append(p, "  up/dn pgup/pgdn --\r\n");
	}
	return append(p, "\033[J");
}

static char *render_tabs(char *p, int view)
{
	p = append(p, "\033[K asm-ebpf   ");
	p = append(p, view == 1 ? "[1 tree]" : " 1 tree ");
	p = append(p, view == 2 ? "[2 pids]" : " 2 pids ");
	p = append(p, view == 3 ? "[3 net]" : " 3 net ");
	p = append(p, view == 4 ? "[4 exec]" : " 4 exec ");
	return p;
}

struct tnode {
	uint32_t pid;
	uint32_t ppid;
};

static struct tnode tnodes[16384];
static int ntnodes;

static int tracked_pid(uint32_t pid)
{
	int i;

	for (i = 0; i < ntnodes; i++)
		if (tnodes[i].pid == pid)
			return 1;
	return 0;
}

static char *tree_node(char *p, int idx, const char *prefix, int is_last,
		       int is_root, int depth, struct win *w)
{
	char comm[32], childpfx[256], line[512], *lp = line;
	int i, kids = 0, seen = 0;

	if (depth > 32)
		return p;
	lp = append(lp, " ");
	lp = append(lp, prefix);
	if (!is_root)
		lp = append(lp, is_last ? "\342\224\224\342\224\200 "
					: "\342\224\234\342\224\200 ");
	if (read_comm(tnodes[idx].pid, comm, sizeof(comm)))
		strcpy(comm, "?");
	lp = append(lp, comm);
	lp = append(lp, "(");
	lp = append_u64(lp, tnodes[idx].pid, 0);
	lp = append(lp, ")");
	*lp = '\0';
	p = win_line(p, w, line);

	if (is_root)
		snprintf(childpfx, sizeof(childpfx), "%.240s", prefix);
	else
		snprintf(childpfx, sizeof(childpfx), "%.240s%s", prefix,
			 is_last ? "   " : "\342\224\202  ");

	for (i = 0; i < ntnodes; i++)
		if (tnodes[i].ppid == tnodes[idx].pid && i != idx)
			kids++;
	for (i = 0; i < ntnodes; i++)
		if (tnodes[i].ppid == tnodes[idx].pid && i != idx)
			p = tree_node(p, i, childpfx, ++seen == kids, 0,
				      depth + 1, w);
	return p;
}

static void render_tree(int rows, int *scroll)
{
	static char buf[65536];
	struct win w = { *scroll, rows - 2, 0, 0 };
	char *p = buf;
	int i;

	ntnodes = snapshot_pids();
	for (i = 0; i < ntnodes; i++) {
		tnodes[i].pid = rows_cur[i].pid;
		tnodes[i].ppid = read_ppid(rows_cur[i].pid);
	}

	p = render_tabs(p, 1);
	p = append(p, "  process tree (tracked pids)\r\n");
	for (i = 0; i < ntnodes; i++)
		if (!tracked_pid(tnodes[i].ppid))
			p = tree_node(p, i, "", 0, 1, 0, &w);
	p = win_footer(p, &w);
	win_clamp(&w, scroll);
	tui_render(buf, p - buf);
}

static char *hexaddr(char *p, unsigned ip, unsigned port)
{
	char num[24];

	num[tui_u64(num, ip & 0xff)] = '\0';
	p = append(p, num);
	p = append(p, ".");
	num[tui_u64(num, (ip >> 8) & 0xff)] = '\0';
	p = append(p, num);
	p = append(p, ".");
	num[tui_u64(num, (ip >> 16) & 0xff)] = '\0';
	p = append(p, num);
	p = append(p, ".");
	num[tui_u64(num, (ip >> 24) & 0xff)] = '\0';
	p = append(p, num);
	p = append(p, ":");
	num[tui_u64(num, port)] = '\0';
	return append(p, num);
}

/* open-addressed inode->pid hash; inode 0 marks an empty slot */
#define SOCKHASH	(1 << 16)
struct sockowner {
	unsigned long inode;
	uint32_t pid;
};

static struct sockowner sockowners[SOCKHASH];
static int nsockowners;

static void sock_insert(unsigned long inode, uint32_t pid)
{
	unsigned h = inode & (SOCKHASH - 1);

	if (!inode || nsockowners >= SOCKHASH - 1)
		return;
	while (sockowners[h].inode && sockowners[h].inode != inode)
		h = (h + 1) & (SOCKHASH - 1);
	if (!sockowners[h].inode)
		nsockowners++;
	sockowners[h].inode = inode;
	sockowners[h].pid = pid;
}

static void scan_sockets(void)
{
	static time_t last;
	time_t now = time(NULL);
	DIR *pd;
	struct dirent *pe;

	if (nsockowners && now == last)	/* rescan at most once a second */
		return;
	last = now;
	nsockowners = 0;
	memset(sockowners, 0, sizeof(sockowners));
	pd = opendir("/proc");
	if (!pd)
		return;
	while ((pe = readdir(pd))) {
		char fdpath[64], *end;
		unsigned long pid = strtoul(pe->d_name, &end, 10);
		DIR *fdd;
		struct dirent *fe;

		if (*end)
			continue;
		snprintf(fdpath, sizeof(fdpath), "/proc/%lu/fd", pid);
		fdd = opendir(fdpath);
		if (!fdd)
			continue;
		while ((fe = readdir(fdd))) {
			char link[96], target[64];
			ssize_t n;

			snprintf(link, sizeof(link), "%.72s/%.20s", fdpath,
				 fe->d_name);
			n = readlink(link, target, sizeof(target) - 1);
			if (n <= 0)
				continue;
			target[n] = '\0';
			if (strncmp(target, "socket:[", 8))
				continue;
			sock_insert(strtoul(target + 8, NULL, 10),
				    (uint32_t)pid);
		}
		closedir(fdd);
	}
	closedir(pd);
}

static uint32_t sock_pid(unsigned long inode)
{
	unsigned h = inode & (SOCKHASH - 1);

	while (sockowners[h].inode) {
		if (sockowners[h].inode == inode)
			return sockowners[h].pid;
		h = (h + 1) & (SOCKHASH - 1);
	}
	return 0;
}


static const char *tcp_state(unsigned st)
{
	static const char *const s[] = {
		"", "ESTAB", "SYN_SENT", "SYN_RECV", "FIN_WAIT1",
		"FIN_WAIT2", "TIME_WAIT", "CLOSE", "CLOSE_WAIT",
		"LAST_ACK", "LISTEN", "CLOSING"
	};

	return st < ARRAY_SIZE(s) ? s[st] : "?";
}

static char *net_file(char *p, const char *path, const char *proto,
		      struct win *w)
{
	char row[320];
	FILE *f = fopen(path, "r");

	if (!f)
		return p;
	if (!fgets(row, sizeof(row), f)) {	/* header */
		fclose(f);
		return p;
	}
	while (fgets(row, sizeof(row), f)) {
		unsigned laddr, lport, raddr, rport, st;
		unsigned long inode = 0;
		uint32_t pid;
		char who[32], comm[16], line[128], *lp = line;

		if (sscanf(row,
			   "%*d: %x:%x %x:%x %x %*x:%*x %*x:%*x %*x %*u %*u %lu",
			   &laddr, &lport, &raddr, &rport, &st, &inode) != 6)
			continue;
		if (!raddr && st != 0x0a)	/* skip closed non-listeners */
			continue;
		pid = sock_pid(inode);
		if (pid && !read_comm(pid, comm, sizeof(comm)))
			snprintf(who, sizeof(who), "%u/%.15s", pid, comm);
		else
			strcpy(who, "-");

		lp = append(lp, " ");
		lp = append_pad(lp, proto, 4);
		lp = append_pad(lp, who, 20);
		lp = hexaddr(lp, laddr, lport);
		lp = append(lp, " -> ");
		lp = hexaddr(lp, raddr, rport);
		lp = append(lp, "  ");
		lp = append(lp, tcp_state(st));
		*lp = '\0';
		p = win_line(p, w, line);
	}
	fclose(f);
	return p;
}

static void render_net(int rows, int *scroll)
{
	static char buf[65536];
	struct win w = { *scroll, rows - 2, 0, 0 };
	char *p = buf;

	scan_sockets();
	p = render_tabs(p, 3);
	p = append(p, "  network connections (pid/comm)\r\n");
	p = net_file(p, "/proc/net/tcp", "tcp", &w);
	p = net_file(p, "/proc/net/udp", "udp", &w);
	p = win_footer(p, &w);
	win_clamp(&w, scroll);
	tui_render(buf, p - buf);
}

static void render_exec(int rows, int cols, int *scroll)
{
	static char buf[65536];
	struct win w = { *scroll, rows - 2, 0, 0 };
	char *p = buf;
	unsigned n = exec_head < EXEC_RING ? exec_head : EXEC_RING;
	unsigned i;
	int wid = cols > 8 && cols < 220 ? cols - 1 : 200;

	p = render_tabs(p, 4);
	p = append(p, "  recent exec, newest first  (short-lived commands land here)\r\n");
	for (i = 0; i < n; i++) {
		unsigned idx = (exec_head - 1 - i) & (EXEC_RING - 1);
		struct execrec *r = &exec_ring[idx];
		double t = start_ts && r->ts >= start_ts ?
			   (r->ts - start_ts) / 1e9 : 0;
		char line[224];

		snprintf(line, sizeof(line), " %10.3f  pid=%-7u %s",
			 t, r->pid, r->cmd);
		line[wid] = '\0';		/* never wrap the terminal */
		p = win_line(p, &w, line);
	}
	p = win_footer(p, &w);
	win_clamp(&w, scroll);
	tui_render(buf, p - buf);
}

static void render_top(int rows, const char *filter, int filt_mode,
		       int trip_mode, int *sel, int *scroll, int paused)
{
	static char buf[65536];
	struct win w;
	char comm[32];
	char *p = buf;
	int n, i, visible = rows - 4;

	if (paused) {
		n = nr_prev;		/* freeze data; arrows just move sel */
	} else {
		n = snapshot_pids();
		qsort(rows_cur, n, sizeof(rows_cur[0]), by_rate);
	}

	if (*sel >= n)
		*sel = n ? n - 1 : 0;
	if (*sel < 0)
		*sel = 0;
	if (*sel < *scroll)
		*scroll = *sel;
	if (*sel >= *scroll + visible)
		*scroll = *sel - visible + 1;
	if (*scroll < 0)
		*scroll = 0;
	w.scroll = *scroll;
	w.visible = visible;
	w.ln = 0;
	w.total = 0;

	p = render_tabs(p, 2);
	if (trip_mode) {
		p = append(p, "  tripwire path: ");
		p = append(p, trip_path);
		p = append(p, "_");
	} else if (filt_mode) {
		p = append(p, "  filter: ");
		p = append(p, filter);
		p = append(p, "_");
	} else {
		if (filter[0]) {
			p = append(p, "  filter=");
			p = append(p, filter);
		}
		if (trip_path[0]) {
			p = append(p, "  TRIP ");
			p = append(p, trip_path);
			p = append(p, " -> SIGKILL");
		}
	}
	p = append(p, paused ? "  [paused]" : "");
	p = append(p, "   enter:detail /:filter t:tripwire q:quit\r\n");
	p = append(p, "\033[K  ");
	p = append_pad(p, "pid", 10);
	p = append_pad(p, "comm", 18);
	p = append_pad(p, "events", 12);
	p = append(p, "evt/s\r\n");

	for (i = 0; i < n; i++) {
		char line[256], *lp = line;

		if (read_comm(rows_cur[i].pid, comm, sizeof(comm)))
			strcpy(comm, "?");
		if (filter[0] && !strstr(comm, filter))
			continue;
		lp = append(lp, i == *sel ? ">" : " ");
		lp = append(lp, " ");
		lp = append_u64(lp, rows_cur[i].pid, 10);
		lp = append_pad(lp, comm, 18);
		lp = append_u64(lp, rows_cur[i].total, 12);
		lp = append_u64(lp, rows_cur[i].rate, 0);
		*lp = '\0';
		p = win_line(p, &w, line);
	}
	p = win_footer(p, &w);

	tui_render(buf, p - buf);

	if (!paused) {
		memcpy(rows_prev, rows_cur, n * sizeof(rows_cur[0]));
		nr_prev = n;
	}
}

static int by_seq_desc(const void *a, const void *b)
{
	uint64_t x = detail_rows[*(const int *)a].seq;
	uint64_t y = detail_rows[*(const int *)b].seq;

	if (x != y)
		return y > x ? 1 : -1;
	return 0;
}

struct trow_edge {
	uint32_t count;
	short a, b;
};

static int by_trans_desc(const void *a, const void *b)
{
	uint32_t x = ((const struct trow_edge *)a)->count;
	uint32_t y = ((const struct trow_edge *)b)->count;

	if (x != y)
		return y > x ? 1 : -1;
	return 0;
}

static uint64_t sum_offcpu(uint32_t tgid)
{
	char path[64];
	uint64_t total = 0, v;
	struct dirent *e;
	DIR *d;

	snprintf(path, sizeof(path), "/proc/%u/task", tgid);
	d = opendir(path);
	if (!d)
		return 0;
	while ((e = readdir(d))) {
		uint32_t tid = atoi(e->d_name);

		if (!tid)
			continue;
		if (!lookup_stat(offcpu_fd, tid, &v))
			total += v;
	}
	closedir(d);
	return total;
}

static void render_detail(int rows, int *scroll)
{
	static char buf[65536];
	struct win w;
	char comm[32];
	char *p = buf;
	int order[DETAIL_ROWS];
	int i, col = 0, nrow = 0, peek_extra = 0;

	if (read_comm(detail_pid, comm, sizeof(comm)))
		strcpy(comm, "?");

	p = append(p, "\033[K asm-ebpf  detail pid=");
	p = append_u64(p, detail_pid, 0);
	p = append(p, " comm=");
	p = append(p, comm);
	p = append(p, "  f:kinds=");
	p = append(p, km_name[detail_km]);
	p = append(p, show_data ? "  d:data=on" : "  d:data=off");
	p = append(p, "   esc:back p:pause q:quit\r\n");
	p = append(p, inject_on ?
		  "\033[K x:inject=ON  openat/connect forced to -EACCES for this pid\r\n"
		: "\033[K x:inject=off (make this pid's openat/connect fail)\r\n");

	p = append(p, "\033[K off-cpu (blocked, all threads): ");
	p = append_u64(p, sum_offcpu(detail_pid) / 1000000, 0);
	p = append(p, " ms\r\n");

	if (peek_mode) {
		peek_extra = 1;
		p += sprintf(p, "\033[K peek user address: 0x%s_\r\n", peek_buf);
	} else if (peek_addr) {
		int row, b;

		peek_extra = 5;
		p += sprintf(p, "\033[K peek user 0x%llx  (r: set addr)%s\r\n",
			     (unsigned long long)peek_addr,
			     peek_have ? "" : "  waiting for a syscall...");
		for (row = 0; row < 4; row++) {
			char asc[17];

			p += sprintf(p, "\033[K  +%02x  ", row * 16);
			for (b = 0; b < 16; b++) {
				unsigned char v = peek_data[row * 16 + b];

				p += sprintf(p, "%02x ", v);
				asc[b] = v >= 0x20 && v < 0x7f ? v : '.';
			}
			asc[16] = '\0';
			p += sprintf(p, " %s\r\n", peek_have ? asc : "");
		}
	}

	p = append(p, "\033[K parents: ");
	p = append(p, comm);
	{
		uint32_t pp = detail_pid;
		int depth;

		for (depth = 0; depth < 8; depth++) {
			uint32_t up = read_ppid(pp);
			char pc[32];

			if (!up || up == pp)
				break;
			p = append(p, " <- ");
			if (read_comm(up, pc, sizeof(pc)))
				strcpy(pc, "?");
			p = append(p, pc);
			p = append(p, "(");
			p = append_u64(p, up, 0);
			p = append(p, ")");
			if (up == 1)
				break;
			pp = up;
		}
	}
	p = append(p, "\r\n");

	p = append(p, "\033[K ");
	for (i = 0; i < (int)ARRAY_SIZE(detail_kind); i++) {
		if (!detail_kind[i] || !evdescs[i].name)
			continue;
		p = append(p, evdescs[i].name);
		p = append(p, "=");
		p = append_u64(p, detail_kind[i], 0);
		p = append(p, "  ");
		if (++col % 6 == 0)
			p = append(p, "\r\n\033[K ");
	}
	p = append(p, show_matrix ?
		   "\r\n\033[K --- behaviour fingerprint: prev -> next syscall  (m: ops) ---\r\n"
		 : "\r\n\033[K --- operations (repeats collapsed)  (m: fingerprint) ---\r\n");

	w.scroll = *scroll;
	w.visible = rows > 7 + peek_extra ? rows - 6 - peek_extra : 1;
	w.ln = 0;
	w.total = 0;

	if (show_matrix) {
		static struct trow_edge edges[TK * TK];
		int ne = 0, a, b;

		for (a = 0; a < (int)TK; a++)
			for (b = 0; b < (int)TK; b++)
				if (trans[a][b]) {
					edges[ne].count = trans[a][b];
					edges[ne].a = a;
					edges[ne].b = b;
					ne++;
				}
		qsort(edges, ne, sizeof(edges[0]), by_trans_desc);
		for (i = 0; i < ne; i++) {
			const char *an = evdescs[edges[i].a].name;
			const char *bn = evdescs[edges[i].b].name;
			char line[160], *lp = line, num[24];

			lp = append(lp, " ");
			lp = append_pad(lp, an ? an : "?", 10);
			lp = append(lp, "-> ");
			lp = append_pad(lp, bn ? bn : "?", 11);
			lp = append(lp, "x");
			num[tui_u64(num, edges[i].count)] = '\0';
			lp = append(lp, num);
			*lp = '\0';
			p = win_line(p, &w, line);
		}
	} else {
		for (i = 0; i < DETAIL_ROWS; i++)
			if (detail_rows[i].count)
				order[nrow++] = i;
		qsort(order, nrow, sizeof(order[0]), by_seq_desc);
		for (i = 0; i < nrow; i++) {
			struct drow *r = &detail_rows[order[i]];
			char line[160], *lp = line, num[24];

			lp = append(lp, " x");
			num[tui_u64(num, r->count)] = '\0';
			lp = append_pad(lp, num, 9);
			lp = append(lp, r->text);
			*lp = '\0';
			p = win_line(p, &w, line);
		}
	}
	p = win_footer(p, &w);
	win_clamp(&w, scroll);
	tui_render(buf, p - buf);
}

static void drain_perf(void)
{
	int i;

	for (i = 0; i < nr_readers; i++)
		read_one(&readers[i]);
}

static void apply_detail_filter(void)
{
	struct filter f;

	memset(&f, 0, sizeof(f));
	f.pid = detail_pid;
	f.kinds = km_mask(detail_km);
	if (inject_on) {
		f.inject_pid = detail_pid;
		f.inject_ret = -EACCES;
	}
	memcpy(f.trip_path, trip_path, sizeof(f.trip_path));
	if (peek_addr) {
		f.peek_addr = peek_addr;
		f.peek_pid = detail_pid;
	}
	set_filter(config_fd, &f);
}

static void arm_tripwire(void)
{
	memcpy(base_filter.trip_path, trip_path, sizeof(base_filter.trip_path));
	if (detail_mode)
		apply_detail_filter();
	else
		set_filter(config_fd, &base_filter);
}

static void enter_detail(uint32_t pid)
{
	drain_perf();			/* discard the pre-filter backlog */
	detail_reset(pid);
	detail_km = KM_ALL;
	inject_on = 0;			/* injection always starts disabled */
	show_matrix = 0;
	peek_addr = 0;
	peek_have = 0;
	apply_detail_filter();
	detail_mode = 1;
}

static void leave_detail(void)
{
	detail_mode = 0;
	if (set_filter(config_fd, &base_filter))
		set_filter(config_fd, &base_filter);
}

static int tui_loop(void)
{
	struct pollfd *fds;
	char filter[32] = { 0 };
	int filt_mode = 0, trip_mode = 0, paused = 0;
	int view = 2, sel = 0, in_detail = 0, scroll = 0;
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
		int key, dirty = 0;
		int nfds = in_detail ? nr_readers + 1 : 1;
		struct pollfd *pf = in_detail ? fds : &fds[nr_readers];
		int ret = poll(pf, nfds, in_detail ? 200 : 500);

		if (ret < 0) {
			if (errno == EINTR)
				break;
			break;
		}
		if (!paused)
			drain_perf();		/* also feeds the exec log */

		while ((key = tui_readkey()) >= 0) {
			dirty = 1;
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
			if (trip_mode) {
				int l = strlen(trip_path);

				if (key == '\r' || key == '\n') {
					trip_mode = 0;
					arm_tripwire();
				} else if (key == 127 || key == 8) {
					if (l)
						trip_path[l - 1] = '\0';
				} else if (key == 27) {
					trip_mode = 0;
					trip_path[0] = '\0';
					arm_tripwire();
				} else if (l < (int)sizeof(trip_path) - 1) {
					trip_path[l] = key;
					trip_path[l + 1] = '\0';
				}
				continue;
			}
			if (peek_mode) {
				int l = strlen(peek_buf);

				if (key == '\r' || key == '\n') {
					peek_mode = 0;
					peek_addr = strtoull(peek_buf, NULL, 16);
					peek_have = 0;
					apply_detail_filter();
				} else if (key == 127 || key == 8) {
					if (l)
						peek_buf[l - 1] = '\0';
				} else if (key == 27) {
					peek_mode = 0;
				} else if (l < (int)sizeof(peek_buf) - 1) {
					peek_buf[l] = key;
					peek_buf[l + 1] = '\0';
				}
				continue;
			}
			if (key == 27) {		/* ESC: arrows or back */
				int k1 = tui_readkey();

				if (k1 == '[') {
					int k2 = tui_readkey();
					int step = (k2 == '5' || k2 == '6') ? 10 : 1;

					if (k2 == '6')		/* PgDn */
						k2 = 'B';
					else if (k2 == '5')	/* PgUp */
						k2 = 'A';
					if (k2 == 'A') {
						if (!in_detail && view == 2) {
							if (sel > 0)
								sel -= step;
							if (sel < 0)
								sel = 0;
						} else if (scroll >= step)
							scroll -= step;
						else
							scroll = 0;
					} else if (k2 == 'B') {
						if (!in_detail && view == 2)
							sel += step;
						else
							scroll += step;
					}
				} else if (in_detail) {
					leave_detail();
					in_detail = 0;
				}
				continue;
			}
			if (key == 'q') {
				if (in_detail) {
					leave_detail();
					in_detail = 0;
				} else
					stop_flag = 1;
			} else if (key == 'p')
				paused = !paused;
			else if (in_detail) {
				if (key == 'f') {
					detail_km = (detail_km + 1) % KM_COUNT;
					apply_detail_filter();
				} else if (key == 'd')
					show_data = !show_data;
				else if (key == 'x') {
					inject_on = !inject_on;
					apply_detail_filter();
				} else if (key == 'm') {
					show_matrix = !show_matrix;
					scroll = 0;
				} else if (key == 'r') {
					peek_mode = 1;
					peek_buf[0] = '\0';
				}
				continue;
			} else if (key == '1') {
				view = 1;
				scroll = 0;
			} else if (key == '2') {
				view = 2;
				scroll = 0;
			} else if (key == '3') {
				view = 3;
				scroll = 0;
			} else if (key == '4') {
				view = 4;
				scroll = 0;
			}
			else if (key == '/' && view == 2) {
				filt_mode = 1;
				filter[0] = '\0';
			} else if (key == 't' && view == 2) {
				trip_mode = 1;
				memset(trip_path, 0, sizeof(trip_path));
			} else if ((key == '\r' || key == '\n') &&
				   view == 2 && sel < nr_prev) {
				enter_detail(rows_cur[sel].pid);
				in_detail = 1;
				scroll = 0;
			}
		}

		if (stop_flag)
			break;

		if (sel >= nr_prev)
			sel = nr_prev ? nr_prev - 1 : 0;

		tui_winsize(&trows, &tcols);
		if (trows < 6)
			trows = 6;

		if (scroll < 0)
			scroll = 0;
		if (in_detail) {
			if (!paused || dirty)
				render_detail(trows, &scroll);
		} else if (!paused || dirty) {
			if (view == 1)
				render_tree(trows, &scroll);
			else if (view == 3)
				render_net(trows, &scroll);
			else if (view == 4)
				render_exec(trows, tcols, &scroll);
			else
				render_top(trows, filter, filt_mode, trip_mode,
					   &sel, &scroll, paused);
		}
	}

	if (in_detail)
		leave_detail();
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
	    errno != ENOENT)
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
	if (patch_map_fd(insns, attr.insn_cnt, BPF_REG_1, 7, pending_fd) &&
	    errno != ENOENT)
		goto err;
	if (patch_map_fd(insns, attr.insn_cnt, BPF_REG_1, 8, fdpath_fd) &&
	    errno != ENOENT)
		goto err;
	if (patch_map_fd(insns, attr.insn_cnt, BPF_REG_2, 9, stack_fd) &&
	    errno != ENOENT)
		goto err;
	if (patch_map_fd(insns, attr.insn_cnt, BPF_REG_1, 10, offstart_fd) &&
	    errno != ENOENT)
		goto err;
	if (patch_map_fd(insns, attr.insn_cnt, BPF_REG_1, 11, offcpu_fd) &&
	    errno != ENOENT)
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
	int j;

	/*
	 * Detach every program first by closing all perf events, so nothing
	 * keeps firing (the sched_switch probe runs on every context switch)
	 * while the slower program frees and kprobe removals proceed.
	 */
	for (i = 0; i < ARRAY_SIZE(targets); i++)
		for (j = 0; j < targets[i].nr_fds; j++)
			if (targets[i].perf_fds)
				close_fd(&targets[i].perf_fds[j]);
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
	close_fd(&pending_fd);
	close_fd(&fdpath_fd);
	close_fd(&stack_fd);
	close_fd(&offstart_fd);
	close_fd(&offcpu_fd);
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
	base_filter = filter;

	load_kallsyms();
	if (nksyms)
		qsort(ksyms, nksyms, sizeof(*ksyms), ksym_cmp);

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
	pending_fd = create_pending_map();
	fdpath_fd = create_fdpath_map();
	stack_fd = create_stack_map();
	offstart_fd = create_off_map();
	offcpu_fd = create_off_map();
	if (count_fd < 0 || bytes_fd < 0 || start_fd < 0 ||
	    hist_fd < 0 || startlat_fd < 0 || pidstat_fd < 0 ||
	    pending_fd < 0 || fdpath_fd < 0 || stack_fd < 0 ||
	    offstart_fd < 0 || offcpu_fd < 0) {
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
	fprintf(stderr, "detaching per-cpu programs...\n");
	detach_all();
	return ret ? 1 : 0;
}
