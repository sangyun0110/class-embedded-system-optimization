#!/usr/bin/env python3
from bcc import BPF
from time import strftime

# //data.filename = vma->vm_file->f_path.dentry->d_name.name;
bpf_text="""
#include <uapi/linux/ptrace.h>
#include <linux/mm.h>

struct data_t {
    char dname[DNAME_INLINE_LEN];
    u64 count;
};

BPF_HASH(counter, const unsigned char*, u64);
BPF_PERF_OUTPUT(events);

int kprobe__handle_mm_fault(struct pt_regs *ctx,
                            struct vm_area_struct *vma,
                            unsigned long address,
                            unsigned int flags) {
    struct data_t data = {};
    struct dentry d;
    u64 *p;
    if(!vma) {
        return 0;
    }
    if(!vma->vm_file) {
        return 0;
    }
    else {
        bpf_probe_read_kernel(&data.dname, sizeof(data.dname), vma->vm_file->f_path.dentry->d_name.name);
        p = counter.lookup(&data.dname);
        if(p == 0)
            data.count = 1;
        else
            data.count = *p + 1;
        counter.update(&data.dname, &data.count);
    }

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

prevEventName = ""
b = BPF(text=bpf_text)
b.attach_kprobe(event="handle_mm_fault", fn_name = "kprobe__handle_mm_fault")
print("%-40s %-8s" % ("FILENAME", "COUNT"))

def print_event(cpu, data, size):
    global prevEventName
    event = b["events"].event(data)
    eventName = event.dname.decode('utf-8')
    if prevEventName != eventName:
        prevEventName = eventName
        print("%-40s %-8s" % (eventName, event.count))

b["events"].open_perf_buffer(print_event)
while True:
    try:
        b.perf_buffer_poll()
    except:
        print("Keyboard Interrupt Catched")
        exit()
