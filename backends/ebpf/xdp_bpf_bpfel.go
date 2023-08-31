// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || amd64p32 || arm || arm64 || mips64le || mips64p32le || mipsle || ppc64le || riscv64
// +build 386 amd64 amd64p32 arm arm64 mips64le mips64p32le mipsle ppc64le riscv64

package ebpf

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadXdp_bpf returns the embedded CollectionSpec for xdp_bpf.
func loadXdp_bpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_Xdp_bpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load xdp_bpf: %w", err)
	}

	return spec, err
}

// loadXdp_bpfObjects loads xdp_bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*xdp_bpfObjects
//	*xdp_bpfPrograms
//	*xdp_bpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadXdp_bpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadXdp_bpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// xdp_bpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type xdp_bpfSpecs struct {
	xdp_bpfProgramSpecs
	xdp_bpfMapSpecs
}

// xdp_bpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type xdp_bpfProgramSpecs struct {
	XdpProgFunc *ebpf.ProgramSpec `ebpf:"xdp_prog_func"`
}

// xdp_bpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type xdp_bpfMapSpecs struct {
	XdpStatsMap *ebpf.MapSpec `ebpf:"xdp_stats_map"`
}

// xdp_bpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadXdp_bpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type xdp_bpfObjects struct {
	xdp_bpfPrograms
	xdp_bpfMaps
}

func (o *xdp_bpfObjects) Close() error {
	return _Xdp_bpfClose(
		&o.xdp_bpfPrograms,
		&o.xdp_bpfMaps,
	)
}

// xdp_bpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadXdp_bpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type xdp_bpfMaps struct {
	XdpStatsMap *ebpf.Map `ebpf:"xdp_stats_map"`
}

func (m *xdp_bpfMaps) Close() error {
	return _Xdp_bpfClose(
		m.XdpStatsMap,
	)
}

// xdp_bpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadXdp_bpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type xdp_bpfPrograms struct {
	XdpProgFunc *ebpf.Program `ebpf:"xdp_prog_func"`
}

func (p *xdp_bpfPrograms) Close() error {
	return _Xdp_bpfClose(
		p.XdpProgFunc,
	)
}

func _Xdp_bpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed xdp_bpf_bpfel.o
var _Xdp_bpfBytes []byte
