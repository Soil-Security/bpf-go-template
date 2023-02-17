# bpf-go-template

A GitHub template repository with the scaffolding for a BPF application developed with [libbpf/libbpf] and BPF CO-RE.
The loader is written in Go and leverages the [cilium/ebpf] library.

A sample BFP code is the Bootstrap application introduced by the [libbpf/libbpf-bootstrap] project. It tracks process
starts and exits and emits data about filename, PID and parent PID, as well as exit status of the process life.

## Usage

Create a new repository from this template by clicking the **Use this template** button in the GitHub interface.
Once it's done, clone and change current directory to the cloned repository:

```
git clone https://github.com/$owner/$repo.git
cd $repo
git submodule update --init --recursive
```

Compile BPF application and Go loader:

```
make -C src all
```

Run the application:

```
sudo ./src/bootstrap
```

If everything is fine, you can start modifying the scaffolding to adjust the Bootstrap application to your needs.

[libbpf/libbpf]: https://github.com/libbpf/libbpf
[libbpf/libbpf-bootstrap]: https://github.com/libbpf/libbpf-bootstrap
[cilium/ebpf]: https://github.com/cilium/ebpf
