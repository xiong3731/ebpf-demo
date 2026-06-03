// 用户态 Agent:加载 BPF 程序、消费 ringbuf 事件、识别容器内可疑 exec 并告警
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"escape-monitor/pkg/event"
)

// 把 C 写的 eBPF 程序编译成字节码,并生成 bpfObjects / loadBpfObjects 等 Go 绑定
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel bpf ../../bpf/exec.bpf.c -- -I../../bpf

// 容器逃逸 / 横向移动相关的可疑命令名 -> 告警原因
var suspicious = map[string]string{
	"nsenter":  "namespace 进入",
	"unshare":  "namespace 分离",
	"mount":    "挂载操作",
	"umount":   "卸载操作",
	"chroot":   "根目录切换",
	"docker":   "容器内调用 docker",
	"kubectl":  "容器内调用 kubectl",
	"runc":     "容器运行时",
	"insmod":   "加载内核模块",
	"modprobe": "加载内核模块",
}

// main 流程:解锁 memlock -> 加载 BPF -> 挂 tracepoint -> 循环消费 ringbuf 事件
func main() {
	// 老内核加载 BPF map 需要 unlimit memlock
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("rlimit: %v", err)
	}

	// 加载 bpf2go 生成的 BPF 对象(programs + maps)到内核
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("load bpf: %v", err)
	}
	defer objs.Close()

	// 将 handle_exec 程序挂到 sched_process_exec tracepoint
	tp, err := link.Tracepoint("sched", "sched_process_exec", objs.HandleExec, nil)
	if err != nil {
		log.Fatalf("attach tracepoint: %v", err)
	}
	defer tp.Close()

	// 打开 ringbuf reader 从内核读事件
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("ringbuf reader: %v", err)
	}
	defer rd.Close()

	// 收到 Ctrl-C / SIGTERM 时关闭 reader,主循环会随之退出
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		_ = rd.Close()
	}()

	log.Println("escape-monitor started, waiting for events...")

	// 主循环:阻塞读一条事件 -> 二进制解码为 Event -> 交给 handle 判断
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("ringbuf closed, exiting")
				return
			}
			log.Printf("read: %v", err)
			continue
		}

		var e event.Event
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e); err != nil {
			log.Printf("decode: %v", err)
			continue
		}
		handle(&e)
	}
}

func handle(e *event.Event) {
	// 将内核事件中的定长 C 字符数组转成 Go 字符串,用于后续规则匹配。
	comm := cstr(e.Comm[:])
	file := cstr(e.Filename[:])

	// 只关注容器内进程;宿主机普通进程直接忽略,降低误报和噪声。
	containerID, inContainer := containerOf(e.Pid)
	if !inContainer {
		return
	}

	// 优先用完整路径中的 basename 匹配可疑命令,避免 /usr/bin/nsenter 这类路径漏报。
	base := comm
	if idx := strings.LastIndex(file, "/"); idx >= 0 {
		base = file[idx+1:]
	}

	// 命中可疑命令表时输出告警;这里只截断容器 ID 方便人工阅读。
	if reason, hit := suspicious[base]; hit {
		short := containerID
		if len(short) > 12 {
			short = short[:12]
		}
		fmt.Printf("[ALERT] container=%s pid=%d uid=%d comm=%s file=%s reason=%q\n",
			short, e.Pid, e.Uid, comm, file, reason)
	}
}

// cstr 去掉内核 C 字符串尾部的 NUL 字节,保留真实命令名/路径。
func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

// containerOf 从 /proc/<pid>/cgroup 路径解析容器 ID。
// 兼容 docker / containerd / cri-o,cgroup v1 与 v2。
func containerOf(pid uint32) (string, bool) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(data), "\n") {
		for _, seg := range strings.Split(line, "/") {
			// systemd scope 和不同运行时会给容器 ID 加前后缀,这里统一剥掉。
			seg = strings.TrimSuffix(seg, ".scope")
			for _, p := range []string{"cri-containerd-", "docker-", "crio-"} {
				seg = strings.TrimPrefix(seg, p)
			}
			if len(seg) == 64 && isHex(seg) {
				return seg, true
			}
		}
	}
	return "", false
}

// isHex 校验 64 位容器 ID 是否为小写十六进制字符串。
func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
