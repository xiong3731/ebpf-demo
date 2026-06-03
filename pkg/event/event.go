package event

// Event 必须与 bpf/exec.bpf.c 中的 struct event 字段顺序、对齐严格一致。
type Event struct {
	Pid      uint32
	Ppid     uint32
	Uid      uint32
	_        uint32 // padding,对齐到 8 字节
	CgroupID uint64
	Comm     [16]byte
	Filename [256]byte
}
