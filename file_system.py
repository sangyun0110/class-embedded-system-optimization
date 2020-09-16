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

enum file_t {
    F_REG,
    F_CHR,
    F_DIR,
    F_FIFO,
    F_BLK,
    F_SOCK,
    F_UNKWN
};


struct data_t {
    enum access_t access_type;
    enum file_t file_type;
    char comm[TASK_COMM_LEN];
    char fname[DNAME_INLINE_LEN];
};

BPF_PERF_OUTPUT(events);

static enum file_t find_type(u32 file_type) {
    if(S_ISREG(file_type))
        return F_REG;
    else if(S_ISCHR(file_type))
        return F_CHR;
    else if(S_ISDIR(file_type))
        return F_DIR;
    else if(S_ISFIFO(file_type))
        return F_FIFO;
    else if(S_ISBLK(file_type))
        return F_BLK;
    else if(S_ISSOCK(file_type))
        return F_SOCK;
    else
        return F_UNKWN;
}

int kprobe__vfs_read(struct pt_regs *ctx,
                     struct file *file,
                     char *buf,
                     size_t count,
                     loff_t *pos) {
    struct data_t data = {};
    data.access_type = FREAD;
    data.file_type = find_type(file->f_inode->i_mode);
    bpf_probe_read_kernel(&data.fname, sizeof(data.fname), file->f_path.dentry->d_name.name);
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
    data.file_type = find_type(file->f_inode->i_mode);
    bpf_probe_read_kernel(&data.fname, sizeof(data.fname), file->f_path.dentry->d_name.name);
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
    data.file_type = find_type(file->f_inode->i_mode);
    bpf_probe_read_kernel(&data.fname, sizeof(data.fname), file->f_path.dentry->d_name.name);
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
    data.file_type = find_type(file->f_inode->i_mode);
    bpf_probe_read_kernel(&data.fname, sizeof(data.fname), file->f_path.dentry->d_name.name);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

# vfs_read, vfs_readv, vfs_write, vfs_write

output = {}
b = BPF(text=bpf_text)
for _event in ['vfs_read', 'vfs_readv', 'vfs_write', 'vfs_writev']:
    b.attach_kprobe(event=_event, fn_name='kprobe__'+_event)

count = 0
def print_event(cpu, data, size):
    global count
    event = b["events"].event(data)
    commandName = event.comm.decode('utf-8')
    if not commandName in output:
        output[commandName] = {'READ': 0, 'WRITE': 0}
    output[commandName]['NAME'] = event.fname
    output[commandName]['WRITE' if event.access_type else 'READ'] += 1
    if not 'TYPE' in output[commandName]:
        output[commandName]['TYPE'] = fileType[event.file_type]

b['events'].open_perf_buffer(print_event)
fileType = ['REG', 'CHR', 'DIR', 'FIFO', 'BLK', 'SOCK', 'UNKNOWN']
while True:
    try:
        b.perf_buffer_poll()
    except:
        print("Keyboard Interrupt Catached")
        print("File Operation Result")
        print("%-20s %-20s %-20s %-20s %-20s" % ('FILENAME', 'COMMAND', 'TYPE', 'READ', 'WRITE'))
        for commandName, result in output.items():
            print("%-20s %-20s %-20s %-20s %-20s" % (result['NAME'].decode('utf-8'), commandName, result['TYPE'], result['READ'], result['WRITE']))
        exit()
