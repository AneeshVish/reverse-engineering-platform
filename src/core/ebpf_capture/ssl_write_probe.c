/* BPF uprobe probe for SSL_write — loaded inline by sniffer.py (reference copy). */
#include <uapi/linux/ptrace.h>
#define MAX_BUF_SIZE 400
#define TASK_COMM_LEN 16

struct ssl_data_t {
    u32 pid;
    u32 uid;
    u64 timestamp_ns;
    u32 len;
    char comm[TASK_COMM_LEN];
    char buf[MAX_BUF_SIZE];
};

BPF_PERF_OUTPUT(ssl_events);

int probe_SSL_write_enter(struct pt_regs *ctx, void *ssl, void *buf, int num) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 uid = bpf_get_current_uid_gid();
    struct ssl_data_t data = {};
    data.pid = pid;
    data.uid = uid;
    data.timestamp_ns = bpf_ktime_get_ns();
    data.len = num > MAX_BUF_SIZE ? MAX_BUF_SIZE : num;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user(&data.buf, data.len, buf);
    ssl_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
