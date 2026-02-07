#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

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


SEC("kprobe/do_sys_openat2")
int BPF_KPROBE(kprobe_do_sys_openat2, int dfd, const char *filename, struct open_how *how)
{
    char fname[128];
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (filename == NULL) {
        return 0; 
    }

    long res = bpf_probe_read_user_str(fname, sizeof(fname), filename);

    if (res > 0) {
        char comm[16];
        bpf_get_current_comm(&comm, sizeof(comm));
        bpf_printk(BPF_TAG  ": PID %d [%s] Open: %s", pid, comm, fname);
    }

    return 0;
}

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

    if(f_size != 0) {
        bpf_printk(BPF_TAG "vfs_read: %s | sz: %lld | req: %lu\n",
               filename, (long long)f_size, (unsigned long)size);
    }

    return 0;
}
char _license[] SEC("license") = "GPL";