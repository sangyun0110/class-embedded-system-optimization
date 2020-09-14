#!/usr/bin/env python3
from bcc import BPF
from time import strftime

bpf_text="""
#include <uapi/linux/ptrace.h>
#include <linux/mm.h>

struct data_t {
    unsigned char *filename;
    u64 count;
    int flag;
};

BPF_HASH(counter, const unsigned char*, u64);
BPF_PERF_OUTPUT(events);

int kprobe__handle_mm_fault(struct pt_regs *ctx,
                            struct vm_area_struct *vma,
                            unsigned long address,
                            unsigned int flags) {
    struct data_t data = {};
    u64 *p;
    if(!vma) {
        return 0;
    }
    if(!vma->vm_file) {
        return 0;
    }
    else {
        data.filename = vma->vm_file->f_path.dentry->d_name.name;
        p = counter.lookup(&data.filename);
        if(p == 0)
            data.count = 1;
        else
            data.count = *p + 1;
        data.flag = 1;
        counter.update(&data.filename, &data.count);
    }

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_kprobe(event="handle_mm_fault", fn_name = "kprobe__handle_mm_fault")
print("FILENAME COUNT")


def print_event(cpu, data, size):
    event = b["events"].event(data)
    if int(event.flag):
        print("%s %s" % (event.filename, event.count))

b["events"].open_perf_buffer(print_event)
while True:
    try:
        b.perf_buffer_poll()
    except:
        print("Keyboard Interrupt Catched")
        exit()
