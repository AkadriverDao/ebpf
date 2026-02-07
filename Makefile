# 1. 定义编译器和工具
CLANG := clang
BPFTOOL := bpftool

# 2. 定义目标架构
ARCH := arm64

# 3. 路径配置（根据你之前的 clang 命令提取）
INCLUDES := -I/usr/include/aarch64-linux-gnu -I.

# 4. 编译选项
# -g: 生成调试信息（BTF 需要）
# -O2: eBPF 必须开启优化，否则无法通过验证
CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES)

# 5. 定义目标文件
BPF_OBJ := task.bpf.o
BPF_SRC := task.bpf.c

# 6. 定义 BPF 文件系统路径
BPF_FS_PATH := /sys/fs/bpf/task_bpf

# --- 编译规则 ---

.PHONY: all clean load unload log

all: $(BPF_OBJ)

# 编译 .c 到 .o
$(BPF_OBJ): $(BPF_SRC)
	@echo "编译 eBPF 程序: $< -> $@"
	$(CLANG) $(CFLAGS) -c $< -o $@

# 一键加载并自动挂载 (autoattach)
load: $(BPF_OBJ)
	@echo "清理旧的挂载点..."
	@rm -f $(BPF_FS_PATH)
	@echo "加载并挂载 BPF 程序..."
	$(BPFTOOL) prog loadall $(BPF_OBJ) $(BPF_FS_PATH) autoattach
	@echo "加载成功！挂载点: $(BPF_FS_PATH)"

# 一键卸载
unload:
	@echo "正在卸载 BPF 程序..."
	@rm -rf $(BPF_FS_PATH)
	@echo "卸载完成。"

# 查看实时日志
log:
	$(BPFTOOL) prog tracelog

# 清理生成文件
clean:
	rm -f *.o