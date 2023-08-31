# bpf-go-template

A GitHub template repository with the scaffolding for a BPF application developed with [libbpf/libbpf] and BPF CO-RE.
The loader is written in Go and leverages the [cilium/ebpf] library.

A sample BFP code is the Bootstrap application introduced by the [libbpf/libbpf-bootstrap] project. It tracks process
starts and exits and emits data about filename, PID and parent PID, as well as exit status of the process life.

[libbpf/libbpf]: https://github.com/libbpf/libbpf
[libbpf/libbpf-bootstrap]: https://github.com/libbpf/libbpf-bootstrap
[cilium/ebpf]: https://github.com/cilium/ebpf
