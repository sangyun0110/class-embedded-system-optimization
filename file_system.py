#!/usr/bin/env python3

from bcc import BPF

# If read/write occured, monitoring which file affected
# 1. Which command access this file
# 2. Which type? (socket, regular, fifo, etc...)
# 3. Which operation? (read/write)
bpf_text="""
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>

enum access_t {
    FREAD,
    FWRITE
};


struct data_t {
    enum access_t access_type;
    u32 file_type;
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

int kprobe__vfs_read(struct pt_regs *ctx,
                     struct file *file,
                     char *buf,
                     size_t count,
                     loff_t *pos) {
    struct data_t data = {};
    data.access_type = FREAD;
    data.file_type = file->f_inode->i_mode & S_IFMT;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}


int kprobe__vfs_readv(struct pt_regs *ctx,
                     struct file *file,
                     const struct iovec *vec,
                     unsigned long vlen,
                     loff_t *pos,
                     rwf_t flags) {
    struct data_t data = {};
    data.access_type = FREAD;
    data.file_type = file->f_inode->i_mode & S_IFMT;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int kprobe__vfs_write(struct pt_regs *ctx,
                     struct file *file,
                     const char *buf,
                     size_t count,
                     loff_t *pos) {
    struct data_t data = {};
    data.access_type = FWRITE;
    data.file_type = file->f_inode->i_mode & S_IFMT;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}


int kprobe__vfs_writev(struct pt_regs *ctx,
                     struct file *file,
                     const struct iovec *vec,
                     unsigned long vlen,
                     loff_t *pos,
                     rwf_t flags) {
    struct data_t data = {};
    data.access_type = FWRITE;
    data.file_type = file->f_inode->i_mode & S_IFMT;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

# vfs_read, vfs_readv, vfs_write, vfs_write
fileType = {
    0o140000: 'SOCK',
    0o120000: 'LNK',
    0o100000: 'REG',
    0o60000: 'BLK',
    0o40000: 'DIR',
    0o20000: 'CHR',
    0o10000: 'FIFO'
}

output = {}
b = BPF(text=bpf_text)
for _event in ['vfs_read', 'vfs_readv', 'vfs_write', 'vfs_writev']:
    b.attach_kprobe(event=_event, fn_name='kprobe__'+_event)

def print_event(cpu, data, size):
    event = b["events"].event(data)
    commandName = event.comm.decode('utf-8')
    if not commandName in output:
        output[commandName] = {'READ': 0, 'WRITE': 0}
    output[commandName]['WRITE' if event.access_type else 'READ'] += 1
    output[commandName]['TYPE'] = fileType.get(event.file_type)


b['events'].open_perf_buffer(print_event)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("Keyboard Interrupt Catached")
        print("File Operation Result")
        print("%-20s %-20s %-20s %-20s" % ('COMMAND', 'TYPE', 'READ', 'WRITE'))
        for commandName, result in output.items():
            if result['TYPE']:
                print("%-20s %-20s %-20s %-20s" % (commandName, result['TYPE'], result['READ'], result['WRITE']))
        exit()
