#!/usr/bin/env python3

from bcc import BPF

# define BPF program
# kernel memory read -> bpf_probe_read_kernel(void *dst, int size, const void *src)
# u64 bpf_ktime_get_ns() -> return current time in nanoseconds
bpf_text ="""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u64 ts;
    u32 pid;
    u64 delta;
    char comm[TASK_COMM_LEN];
};

BPF_HASH(birth, u32);
BPF_PERF_OUTPUT(events);

int kprobe__io_schedule(struct pt_regs *ctx) {
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    birth.update(&data.pid, &data.ts);
    data.delta = 0;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

int kretprobe__io_schedule(struct pt_regs *ctx) {
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    u64 *tsp, delta;
    tsp = birth.lookup(&data.pid);
    if(tsp == 0) {
        return 0; // missed create
    }
    data.delta = (data.ts - *tsp);
    birth.delete(&data.pid);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""


# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="io_schedule", fn_name="kprobe__io_schedule")
b.attach_kprobe(event="io_schedule", fn_name="kretprobe__io_schedule")

print("%-16s %-16s %-16s %-16s" % ("TIME", "PID", "DELTA(ms)", "COMM"))

def print_event(cpu, data, size):
    event = b["events"].event(data)
    if event.delta:
        print("%-16s %-16s %-16s %-16s" % (event.ts, event.pid, event.delta / 1000000, event.comm.decode('utf-8', 'replace')))

b["events"].open_perf_buffer(print_event)
while True:
    try:
        b.perf_buffer_poll()
    except:
        print("Keyboard Interrupt Catched")
        exit()
