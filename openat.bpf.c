#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
// clang -O2 -g -target bpf -D__TARGET_ARCH_arm64 \
//       -I/usr/include/aarch64-linux-gnu \
//       -c openat.bpf.c -o openat.bpf.o

// clang -O2 -g -target bpf -D__TARGET_ARCH_arm64 \
//       -I/usr/include/aarch64-linux-gnu \
//       -c openat.bpf.c -o openat_watch.bpf.o

// 根据你刚才提供的 format 手动定义结构体
// struct openat_args {
//     unsigned short common_type;
//     unsigned char common_flags;
//     unsigned char common_preempt_count;
//     int common_pid;
//     int __syscall_nr;
    
//     // 注意：根据 format，这里从 offset 12 到 16 之间有 4 字节空隙（padding）
//     // 或者直接按照 offset 16 开始定义字段
//     long dfd;               // offset 16
//     const char *filename;   // offset 24
//     long flags;             // offset 32
//     long mode;              // offset 40
// };

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

// char _license[] SEC("license") = "GPL";

SEC("kprobe/do_sys_openat2")
int BPF_KPROBE(kprobe_do_sys_openat2, int dfd, const char *filename, struct open_how *how)
{
    char fname[128];
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // --- 关键的判空开始 ---
    // 告诉验证器：如果 filename 是 NULL，我们立刻退出，不进行后续内存读取
    if (filename == NULL) {
        return 0; 
    }
    // --- 关键的判空结束 ---

    // 此时验证器知道 filename 不为 0，才允许你调用辅助函数
    long res = bpf_probe_read_user_str(fname, sizeof(fname), filename);

    if (res > 0) {
        // 获取进程名用于展示
        char comm[16];
        bpf_get_current_comm(&comm, sizeof(comm));
        
        bpf_printk("WATCH: PID %d [%s] Open: %s", pid, comm, fname);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";