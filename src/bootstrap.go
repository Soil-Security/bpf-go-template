package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

func main() {
	if err := run(setupHandler()); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s", err.Error())
		os.Exit(1)
	}
	os.Exit(0)
}

func run(ctx context.Context) error {
	var bpfObjects bpfObjects

	executable, err := os.Executable()
	if err != nil {
		return err
	}
	bpfObjectFile := path.Join(filepath.Dir(executable), "bootstrap.bpf.o")

	spec, err := ebpf.LoadCollectionSpec(bpfObjectFile)
	if err != nil {
		return err
	}

	err = spec.LoadAndAssign(&bpfObjects, &ebpf.CollectionOptions{})
	if err != nil {
		return err
	}
	defer bpfObjects.Close()

	ringbufReader, err := ringbuf.NewReader(bpfObjects.EventsMap)
	if err != nil {
		return err
	}
	defer ringbufReader.Close()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				record, err := ringbufReader.Read()
				if err != nil {
					if errors.Is(err, ringbuf.ErrClosed) {
						return
					}
					continue
				}

				printRecord(record.RawSample)
			}
		}
	}()

	bpfObjects.ProcessExecLink, err = link.Tracepoint("sched", "sched_process_exec", bpfObjects.ProcessExecProg, nil)
	if err != nil {
		return err
	}

	bpfObjects.ProcessExitLink, err = link.Tracepoint("sched", "sched_process_exit", bpfObjects.ProcessExitProg, nil)
	if err != nil {
		return err
	}

	<-ctx.Done()

	return nil
}

func printRecord(raw []byte) {
	offset := 0
	pid := int(binary.LittleEndian.Uint32(raw[offset : offset+4]))
	offset += 4
	ppid := int(binary.LittleEndian.Uint32(raw[offset : offset+4]))
	offset += 4

	fmt.Printf("%d\t%d\n", pid, ppid)
}

var onlyOneSignalHandler = make(chan struct{})

func setupHandler() context.Context {
	close(onlyOneSignalHandler)

	ctx, cancel := context.WithCancel(context.Background())

	c := make(chan os.Signal, 2)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-c
		cancel()
		<-c
		os.Exit(1)
	}()

	return ctx
}

type bpfObjects struct {
	bpfPrograms
	bpfLinks
	bpfMaps
}

func (o *bpfObjects) Close() error {
	return bpfClose(
		&o.bpfPrograms,
		&o.bpfLinks,
		&o.bpfMaps,
	)
}

type bpfPrograms struct {
	ProcessExecProg *ebpf.Program `ebpf:"handle_exec"`
	ProcessExitProg *ebpf.Program `ebpf:"handle_exit"`
}

func (p *bpfPrograms) Close() error {
	return bpfClose(
		p.ProcessExecProg,
		p.ProcessExitProg,
	)
}

type bpfLinks struct {
	ProcessExecLink link.Link
	ProcessExitLink link.Link
}

func (l *bpfLinks) Close() error {
	return bpfClose(
		l.ProcessExecLink,
		l.ProcessExitLink,
	)
}

type bpfMaps struct {
	EventsMap *ebpf.Map `ebpf:"events"`
}

func (m *bpfMaps) Close() error {
	return bpfClose(
		m.EventsMap,
	)
}

func bpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}
