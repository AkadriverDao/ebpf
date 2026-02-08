#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

// SEC("tracepoint/syscalls/sys_enter_openat")
// int bpf_trace_openat(struct trace_event_raw_sys_enter *ctx)
// {
//     // 初始化栈空间，这是比判空更实际的安全操作
//     char comm[16] = {0}; 
//     char fname[64] = {0};

//     // 获取进程名（不需要判空，但可以检查返回值）
    // if (bpf_get_current_comm(&comm, sizeof(comm)) < 0) {
    //     // 如果拷贝失败，可以用默认值
    //     __builtin_memcpy(comm, "unknown", 8);
    // }

//     const char *filename_ptr = (const char *)ctx->args[1];
//     if (!filename_ptr) return 0; // 指针判空：生死攸关

//     if (bpf_probe_read_user_str(fname, sizeof(fname), filename_ptr) < 0) {
//         return 0; // 读取校验：逻辑闭环
//     }

//     bpf_printk("PID %d [%s] Open: %s", bpf_get_current_pid_tgid() >> 32, comm, fname);
//     return 0;
// }

#define BPF_TAG "TASK_BPF"


// SEC("kprobe/do_sys_openat2")
// int BPF_KPROBE(kprobe_do_sys_openat2, int dfd, const char *filename, struct open_how *how)
// {
//     char fname[128];
//     u32 pid = bpf_get_current_pid_tgid() >> 32;

//     if (filename == NULL) {
//         return 0; 
//     }

//     long res = bpf_probe_read_user_str(fname, sizeof(fname), filename);

//     if (res > 0) {
//         char comm[16];
//         bpf_get_current_comm(&comm, sizeof(comm));
//         bpf_printk(BPF_TAG  ": PID %d [%s] Open: %s", pid, comm, fname);
//     }

//     return 0;
// }

SEC("kprobe/vfs_read")
int BPF_KPROBE(kprobe_vfs_read, struct file *file, char *buf, size_t size, loff_t *offset) 
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0) return 0;

    if (!file) return 0;

    struct dentry *de = BPF_CORE_READ(file, f_path.dentry);
    if (!de) return 0;

    const unsigned char *n_ptr = BPF_CORE_READ(de, d_name.name);
    if (!n_ptr) return 0;

    char filename[64];
    __builtin_memset(filename, 0, sizeof(filename));
    
    long len = bpf_probe_read_kernel_str(filename, sizeof(filename), n_ptr);
    if (len <= 0) return 0;

    // 3. 读取 inode 属性
    struct inode *in = BPF_CORE_READ(file, f_inode);
    if (!in) return 0;
    long long f_size = BPF_CORE_READ(in, i_size);

    // if(f_size != 0) {
    //     bpf_printk(BPF_TAG "vfs_read: %s | sz: %lld | req: %lu\n",
    //            filename, (long long)f_size, (unsigned long)size);
    // }

    return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(kprobe_tcp_v4_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0) return 0;

    if (!uaddr) return 0;


    unsigned short family = 0;
    if (bpf_probe_read_user(&family, sizeof(family), &uaddr->sa_family) != 0) {
        if(bpf_probe_read_kernel(&family, sizeof(family), &uaddr->sa_family) != 0) {
            bpf_printk(BPF_TAG " tcpv %u", family);
            return 0;
        }
    }

    if (family != 2) return 0;
    struct sockaddr_in uservaddr;
    __builtin_memset(&uservaddr, 0, sizeof(uservaddr));

    if (bpf_probe_read_kernel(&uservaddr, sizeof(uservaddr), uaddr) != 0) {
        return 0;
    }

    u32 daddr = uservaddr.sin_addr.s_addr;
    u16 dport = uservaddr.sin_port;


    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk(BPF_TAG ": [%s] PID:%d Connect -> %pI4:%u\n", 
               comm, pid, &daddr, bpf_ntohs(dport));

    return 0;
}

SEC("kprobe/submit_bio")
int BPF_KPROBE(submit_bio_entry, struct bio *bio)
{
    if(bio == NULL) return 0;
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    u32 opf = BPF_CORE_READ(bio, bi_opf);
    u32 op_code = opf & 0xff; // 获取低位操作码

    if (op_code == 0)
        bpf_printk(BPF_TAG " %s submit_bio READ",comm);
    else if (op_code == 1)
        bpf_printk(BPF_TAG " %s submit_bio WRITE", comm);
    else if (op_code == 3)
        bpf_printk(BPF_TAG " %s submit_bio DISCARD", comm);
    else if (op_code == 9)
        bpf_printk(BPF_TAG " %s submit_bio FLUSH", comm);
    else
        bpf_printk(BPF_TAG " %s submit_bio UNKNOWN:%u", comm, op_code);
    return 0;
}

char _license[] SEC("license") = "GPL";