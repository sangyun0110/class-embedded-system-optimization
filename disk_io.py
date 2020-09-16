#!/usr/bin/env python3

from bcc import BPF

# monitoring I/O opreation pattern(RANDOM/SEQUENTIAL)
bpf_text="""
#include <uapi/linux/ptrace.h>
#include <linux/blk-mq.h>

struct data_t {
    char disk[DISK_NAME_LEN];
    char name[TASK_COMM_LEN];
    u32 total_data_len;
    u64 sector;
    u64 nr_sector;
    u64 rwflag;
};
BPF_HASH(worker, char *, u64);
BPF_PERF_OUTPUT(events);

int kprobe__blk_mq_start_request(struct pt_regs *ctx,
                                 struct request *rq) {
    struct data_t data = {};
    data.sector = rq->__sector;
    data.total_data_len = rq->__data_len;
    bpf_get_current_comm(&data.name, sizeof(data.name));

    #ifdef REQ_WRITE
        data.rwflag = !!(rq->cmd_flags & REQ_WRITE);
    #elif defined(REQ_OP_SHIFT)
        data.rwflag = !!((rq->cmd_flags >> REQ_OP_SHIFT) == REQ_OP_WRITE);
    #else
        data.rwflag = !!((rq->cmd_flags & REQ_OP_MASK) == REQ_OP_WRITE);
    #endif
    data.nr_sector = rq->queue_depth;
    bpf_probe_read_kernel(data.disk, sizeof(rq->rq_disk->disk_name), rq->rq_disk->disk_name);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

sectorMap = []

b = BPF(text=bpf_text)
b.attach_kprobe(event='blk_mq_start_request', fn_name='kprobe__blk_mq_start_request')
print("%-20s %-16s %-20s %-20s %-20s" % ('COMMAND', 'DISK', 'SECTOR', 'DATA_LEN', 'OPERATION'))

def print_event(cpu, data, size):
    event = b['events'].event(data)
    if event.sector != 18446744073709551615 and event.sector not in sectorMap:
        sectorMap.append(event.sector)
        print('%-20s %-16s %-20s %-20s %-20s %-20s' % (event.name.decode('utf-8'), event.disk.decode('utf-8'), hex(event.sector), hex(event.total_data_len), event.rwflag, event.nr_sector))

b['events'].open_perf_buffer(print_event)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
