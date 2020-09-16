#!/usr/bin/env python3

from bcc import BPF
import threading
# monitoring I/O opreation pattern(RANDOM/SEQUENTIAL)
bpf_text="""
#include <uapi/linux/ptrace.h>
#include <linux/blk-mq.h>

struct data_t {
    char disk[DISK_NAME_LEN];
    //char name[TASK_COMM_LEN];
    u64 total_data_len;
    u64 sector;
    u64 rwflag;
    //u64 srflag;
    //u64 prev;
};
//BPF_HASH(prev_sector, u64, u64);
//BPF_HASH(prev_length, u64, u64);
BPF_PERF_OUTPUT(events);

int kprobe__blk_mq_start_request(struct pt_regs *ctx,
                                 struct request *rq) {
    struct data_t data = {};
    data.sector = rq->__sector;
    data.total_data_len = rq->__data_len >> 9;
    #ifdef REQ_WRITE
        data.rwflag = !!(rq->cmd_flags & REQ_WRITE);
    #elif defined(REQ_OP_SHIFT)
        data.rwflag = !!((rq->cmd_flags >> REQ_OP_SHIFT) == REQ_OP_WRITE);
    #else
        data.rwflag = !!((rq->cmd_flags & REQ_OP_MASK) == REQ_OP_WRITE);
    #endif
    bpf_probe_read_kernel(data.disk, sizeof(rq->rq_disk->disk_name), rq->rq_disk->disk_name);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

sectorMap = {}
diskMap = {}
b = BPF(text=bpf_text)
b.attach_kprobe(event='blk_mq_start_request', fn_name='kprobe__blk_mq_start_request')
print("%-20s %-20s %-20s %-20s %-20s" % ('DISK', 'READ', 'WRITE', 'SEQUENTIAL', 'RANDOM'))

totalCount = 0
def print_event(cpu, data, size):
    global totalCount
    event = b['events'].event(data)
    if event.sector == 18446744073709551615:
        return
    if not event.disk in diskMap:
        diskMap[event.disk] = {
            'READ': 0,
            'WRITE': 0,
            'RANDOM': 0,
            'SEQUENTIAL': 0,
            'PREV_SECTOR': event.sector,
            'DATA_LEN': event.total_data_len
        }
    else:
        if diskMap[event.disk]['PREV_SECTOR'] == event.sector:
            return
        if diskMap[event.disk]['PREV_SECTOR'] + diskMap[event.disk]['DATA_LEN'] == event.sector:
            diskMap[event.disk]['SEQUENTIAL'] += 1
        else:
            diskMap[event.disk]['RANDOM'] += 1
        diskMap[event.disk]['PREV_SECTOR'] = event.sector
        diskMap[event.disk]['DATA_LEN'] = event.total_data_len
    # print('%-20s %-20s' % (event.sector, event.total_data_len))

    flag = 'WRITE' if event.rwflag else 'READ'
    diskMap[event.disk][flag] += 1
    totalCount += 1
    if totalCount == 100:
        totalCount = 0
        print_result()

b['events'].open_perf_buffer(print_event)

def print_result():
    b.perf_buffer_poll()
    for key, value in diskMap.items():
        print('%-20s %-20s %-20s %-20s %-20s' % (key.decode('utf-8'), value['READ'], value['WRITE'], value['SEQUENTIAL'], value['RANDOM']))

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        print('Keyboard Interrupt Catched')
        print("%-20s %-20s %-20s %-20s %-20s" % ('DISK', 'READ', 'WRITE', 'SEQ(%)', 'RANDOM(%)'))
        for key, value in diskMap.items():
            total = value['SEQUENTIAL'] + value['RANDOM']
            print('%-20s %-20s %-20s %-20s %-20s' % (key.decode('utf-8'), value['READ'], value['WRITE'], value['SEQUENTIAL']*100/total, value['RANDOM']*100/total))
        exit()
