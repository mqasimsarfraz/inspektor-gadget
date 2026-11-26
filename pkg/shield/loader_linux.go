// Copyright 2026 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux && !withoutebpf

package shield

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"runtime"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	ebpfutils "github.com/inspektor-gadget/inspektor-gadget/pkg/utils/ebpf"
)

const verifierLogSize = 16 << 20

type Run struct {
	closers []io.Closer
}

func (r *Run) Close() error {
	var errs []error
	for idx := len(r.closers) - 1; idx >= 0; idx-- {
		errs = append(errs, r.closers[idx].Close())
	}
	r.closers = nil
	return errors.Join(errs...)
}

// Load executes already authenticated artifacts. Image authorization is the
// caller's responsibility; this does not implement Shirudo kernel enforcement.
func Load(ctx context.Context, pkg *Package) (result *Run, err error) {
	run := &Run{}
	defer func() {
		if err != nil {
			err = errors.Join(err, run.Close())
		}
	}()
	for _, patch := range pkg.Patches {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := run.loadPatch(ctx, patch); err != nil {
			return nil, fmt.Errorf("applying patch %q: %w", patch.Name, err)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return run, nil
}

func (r *Run) loadPatch(ctx context.Context, patch *Patch) error {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return fmt.Errorf("unsupported loader architecture %q", runtime.GOARCH)
	}
	dataMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Name: "shield_data", Type: ebpf.Array, KeySize: 4,
		ValueSize: uint32(len(patch.data)), MaxEntries: 1,
	})
	if err != nil {
		return fmt.Errorf("creating loader data map: %w", err)
	}
	r.closers = append(r.closers, dataMap)
	if err := dataMap.Put(uint32(0), patch.data); err != nil {
		return fmt.Errorf("initializing loader data map: %w", err)
	}
	log := make([]byte, verifierLogSize)
	loader, err := loadProgram(patch.loader, dataMap.FD(), log)
	if err != nil {
		return fmt.Errorf("loading syscall loader (kernel must support BPF_PROG_TYPE_SYSCALL): %w", err)
	}
	r.closers = append(r.closers, loader)
	le := binary.LittleEndian
	progOffset := 24 + 16*int(patch.maps)
	// The gen_loader ABI has a 24-byte context, 16-byte map descriptors,
	// 4-byte program descriptors, and can access beyond the descriptor tail.
	buf := make([]byte, progOffset+4*len(patch.programs)+1024)
	for idx := range int(patch.maps) {
		le.PutUint32(buf[24+16*idx:], ^uint32(0))
	}
	for idx := range patch.programs {
		le.PutUint32(buf[progOffset+4*idx:], ^uint32(0))
	}
	le.PutUint32(buf, uint32(len(buf)))
	le.PutUint32(buf[8:], 1)
	le.PutUint32(buf[12:], uint32(len(log)))
	le.PutUint64(buf[16:], bytePointer(log))
	retval, err := loader.Run(&ebpf.RunOptions{Context: buf, ContextOut: buf})
	runtime.KeepAlive(log)
	if err != nil {
		return fmt.Errorf("running syscall loader: %w; verifier: %s", err, verifierLog(log))
	}
	if int32(retval) < 0 {
		// gen_loader closes its created FDs on this path. The descriptor
		// tail contains stale numbers and must not be closed a second time.
		return fmt.Errorf("payload loader: %w; verifier: %s", unix.Errno(-int32(retval)), verifierLog(log))
	}
	var fds []int
	seen := make(map[int]bool)
	var descriptorErrors []error
	for idx := 0; idx < int(patch.maps)+len(patch.programs); idx++ {
		offset := 24 + 16*idx
		if idx >= int(patch.maps) {
			offset = progOffset + 4*(idx-int(patch.maps))
		}
		fd := int(int32(le.Uint32(buf[offset:])))
		if fd < 3 || fd == dataMap.FD() || fd == loader.FD() || seen[fd] {
			descriptorErrors = append(descriptorErrors, fmt.Errorf("loader returned invalid or duplicate descriptor %d", fd))
			continue
		}
		seen[fd] = true
		fds = append(fds, fd)
		r.closers = append(r.closers, &ownedFD{fd: fd})
	}
	if err := errors.Join(descriptorErrors...); err != nil {
		return err
	}
	programs := make([]*ebpf.Program, 0, len(patch.programs))
	for idx, fd := range fds {
		dup, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("duplicating payload descriptor: %w", err)
		}
		if idx < int(patch.maps) {
			m, err := ebpf.NewMapFromFD(dup)
			if err != nil {
				return fmt.Errorf("adopting payload map: %w", err)
			}
			r.closers = append(r.closers, m)
			continue
		}
		p, err := ebpf.NewProgramFromFD(dup)
		if err != nil {
			return fmt.Errorf("adopting payload program: %w", err)
		}
		r.closers = append(r.closers, p)
		kind := patch.programs[idx-int(patch.maps)]
		if kind == 0 && p.Type() != ebpf.LSM || kind == 5 && p.Type() != ebpf.Tracing {
			return fmt.Errorf("program %d type %s is not a supported LSM/fmod_ret mitigation", idx-int(patch.maps), p.Type())
		}
		programs = append(programs, p)
	}
	for idx, program := range programs {
		if err := ctx.Err(); err != nil {
			return err
		}
		var l link.Link
		if patch.programs[idx] == 5 {
			l, err = ebpfutils.AttachModifyReturn(program)
		} else {
			l, err = ebpfutils.AttachLSM(program)
		}
		if err != nil {
			return fmt.Errorf("attaching program %d (%s): %w", idx, program.Type(), err)
		}
		r.closers = append(r.closers, l)
	}
	return nil
}

type ownedFD struct{ fd int }

func (f *ownedFD) Close() error {
	if f.fd < 0 {
		return nil
	}
	fd := f.fd
	f.fd = -1
	return unix.Close(fd)
}

func bytePointer(b []byte) uint64 {
	return uint64(uintptr(unsafe.Pointer(&b[0])))
}

func verifierLog(b []byte) string {
	if idx := bytes.IndexByte(b, 0); idx >= 0 {
		b = b[:idx]
	}
	return string(b)
}

func loadProgram(insns []byte, mapFD int, log []byte) (*ebpf.Program, error) {
	// BPF_PROG_LOAD through fd_array at offset 120. Signature/keyring
	// attributes are intentionally absent; IG verifies the enclosing image.
	attr := struct {
		ProgType, InsnCount uint32
		Insns, License      uint64
		LogLevel, LogSize   uint32
		LogBuf              uint64
		KernelVersion       uint32
		Flags               uint32
		Name                [16]byte
		Reserved            [56]byte
		FDArray             uint64
	}{
		ProgType: uint32(ebpf.Syscall), InsnCount: uint32(len(insns) / 8), Insns: bytePointer(insns),
		LogLevel: 1, LogSize: uint32(len(log)), LogBuf: bytePointer(log), Flags: 1 << 4,
	}
	license := []byte("Dual BSD/GPL\x00")
	fdArray := []int32{int32(mapFD)}
	attr.License = bytePointer(license)
	attr.FDArray = uint64(uintptr(unsafe.Pointer(&fdArray[0])))
	copy(attr.Name[:], "shield_loader")
	fd, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_PROG_LOAD, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	runtime.KeepAlive(insns)
	runtime.KeepAlive(license)
	runtime.KeepAlive(fdArray)
	runtime.KeepAlive(log)
	if errno != 0 {
		return nil, fmt.Errorf("%w; verifier: %s", errno, verifierLog(log))
	}
	return ebpf.NewProgramFromFD(int(fd))
}
