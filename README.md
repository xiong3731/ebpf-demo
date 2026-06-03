# ebpf-demo

一个用于学习和演示的 eBPF 容器异常进程监控项目。

项目通过 eBPF 监听 Linux 进程 `execve` 成功事件，在用户态判断该进程是否来自容器，并对容器内执行的高风险命令输出告警。适合理解 eBPF tracepoint、ringbuf、CO-RE 以及 Go 用户态程序如何协作。

## 核心能力

- 基于 `sched_process_exec` tracepoint 捕获进程执行事件。
- 通过 ringbuf 将内核态事件高效传递到 Go 用户态 Agent。
- 解析 `/proc/<pid>/cgroup` 判断进程是否运行在容器中。
- 兼容常见容器运行时 ID 格式: Docker、containerd、CRI-O。
- 对容器内可疑命令输出告警，例如 `nsenter`、`unshare`、`mount`、`chroot`、`docker`、`kubectl`、`runc`、`insmod`、`modprobe`。

## 工作原理

```text
进程 execve 成功
      |
      v
sched_process_exec tracepoint
      |
      v
eBPF 程序采集 pid / ppid / uid / comm / filename / cgroup_id
      |
      v
ringbuf 发送事件到用户态
      |
      v
Go Agent 解码事件
      |
      v
读取 /proc/<pid>/cgroup 判断是否为容器进程
      |
      v
命中可疑命令规则后输出告警
```

## 目录结构

```text
.
├── bpf/
│   └── exec.bpf.c        # 内核态 eBPF 程序
├── cmd/
│   └── agent/
│       └── main.go       # Go 用户态 Agent
├── pkg/
│   └── event/
│       └── event.go      # 与 C struct event 对齐的 Go 事件结构
├── Makefile              # 构建、生成、运行入口
├── go.mod
└── README.md
```

## 环境要求

建议在 Linux 主机或支持 eBPF 的虚拟机中运行。

- Linux kernel 5.8+，项目使用 `BPF_MAP_TYPE_RINGBUF`。
- 内核开启 BTF，通常需要 `/sys/kernel/btf/vmlinux` 存在。
- Go 1.20+。
- `clang`、`llvm`、`bpftool`。
- 运行时需要 root 权限或具备加载 eBPF 程序的能力。

Ubuntu / Debian 可参考:

```bash
sudo apt-get update
sudo apt-get install -y clang llvm bpftool make
```

## 构建与运行

首次构建前先从当前内核导出 CO-RE 需要的 `vmlinux.h`:

```bash
make vmlinux
```

编译 eBPF 程序并构建 Go Agent:

```bash
make build
```

运行监控程序:

```bash
sudo make run
```

启动成功后会看到类似输出:

```text
escape-monitor started, waiting for events...
```

## 验证方式

另开一个终端，启动测试容器:

```bash
docker run --rm -it alpine sh
```

在容器内执行可疑命令，例如:

```bash
mount
chroot / /bin/sh
```

Agent 终端预期输出类似:

```text
[ALERT] container=abc123def456 pid=1234 uid=0 comm=mount file=/bin/mount reason="挂载操作"
```

## 常用命令

```bash
make vmlinux   # 生成 bpf/vmlinux.h
make generate  # 调用 bpf2go 生成 Go 绑定和 BPF 字节码
make build     # 构建最终 Agent
sudo make run  # 构建并运行 Agent
make clean     # 清理生成产物
```

## 当前限制

- 目前只监听 `execve` 成功事件，不覆盖所有容器逃逸行为。
- 容器识别依赖 `/proc/<pid>/cgroup` 中的 64 位容器 ID。
- 告警规则是静态命令名匹配，未包含参数级别判断。
- 只输出到标准输出，未接入日志系统、Prometheus、Kafka 或 SIEM。
- `cgroup_id` 已在内核态采集，但当前用户态主要依赖 `/proc` 解析容器 ID。

## 可扩展方向

- 增加 `mount`、`setns`、`capable`、`ptrace` 等 hook，覆盖更多逃逸行为。
- 接入 Kubernetes API，根据容器 ID 补全 Pod、Namespace、Node 等元数据。
- 增加白名单规则，过滤 kubelet、runtime shim、init 流程中的合法行为。
- 支持 JSON 输出，方便对接日志采集和告警平台。
- 将规则配置外置化，支持热更新和按环境调整。

## 免责声明

该项目用于学习和演示 eBPF 安全监控思路，不建议未经改造直接用于生产环境。生产落地需要补充规则治理、性能压测、误报处理、权限控制和审计链路。
