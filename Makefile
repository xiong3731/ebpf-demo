.PHONY: vmlinux tidy generate build run clean

BIN := bin/agent

# 从当前内核导出 CO-RE 需要的类型定义,供 eBPF C 程序编译使用。
vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

tidy:
	go mod tidy

# 先整理依赖,再执行 go:generate 调用 bpf2go 生成 Go 绑定和 BPF 字节码。
generate: tidy
	cd cmd/agent && go generate ./...

# 生成 BPF 产物后编译用户态 agent。
build: generate
	mkdir -p bin
	go build -o $(BIN) ./cmd/agent

# 运行 agent 需要加载 eBPF 程序,通常需要 root 权限。
run: build
	sudo ./$(BIN)

# 清理二进制和 bpf2go 生成文件,保留源码。
clean:
	rm -rf bin cmd/agent/bpf_*.go cmd/agent/bpf_*.o
