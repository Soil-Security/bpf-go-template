package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	bpfevents "github.com/danielpacak/bpf-events"
)

//go:embed bootstrap.bpf.o
var bpfELFBytes []byte

func main() {
	if err := run(setupHandler()); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s", err.Error())
		os.Exit(1)
	}
	os.Exit(0)
}

func run(ctx context.Context) error {
	var bpfObjects bpfObjects

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfELFBytes))
	if err != nil {
		return err
	}
	decoder := &bpfevents.Decoder{ByteOrder: spec.ByteOrder}

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

				err = parseAndPrintEvent(record.RawSample, decoder)
				if err != nil {
					fmt.Fprintf(os.Stderr, "error: failed parsing and printing event: %v\n", err)
					continue
				}
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

func parseAndPrintEvent(buf []byte, decoder *bpfevents.Decoder) error {
	e := event{}
	err := e.unpack(buf, decoder)
	if err != nil {
		return fmt.Errorf("failed unpacking event: %w", err)
	}
	j, err := e.toJSON()
	if err != nil {
		return fmt.Errorf("failed converting event to JSON: %w", err)
	}
	_, err = fmt.Println(j)
	return err
}

type event struct {
	Pid        int
	PPid       int
	ExitCode   int
	DurationNs int
	Comm       string
	FileName   string
}

func (e *event) unpack(buf []byte, decoder *bpfevents.Decoder) error {
	var off = 0
	var err error

	e.Pid, off, err = decoder.Uint32AsInt(buf, off)
	if err != nil {
		return err
	}

	e.PPid, off, err = decoder.Uint32AsInt(buf, off)
	if err != nil {
		return err
	}

	e.ExitCode, off, err = decoder.Uint32AsInt(buf, off)
	if err != nil {
		return err
	}

	e.DurationNs, off, err = decoder.Uint64AsInt(buf, off)
	if err != nil {
		return err
	}

	e.Comm, off, err = decoder.Str(buf, off, 16)
	if err != nil {
		return err
	}

	e.FileName, _, err = decoder.Str(buf, off, 127)
	if err != nil {
		return err
	}

	return nil
}

func (e *event) toJSON() (string, error) {
	j, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	return string(j), nil
}
