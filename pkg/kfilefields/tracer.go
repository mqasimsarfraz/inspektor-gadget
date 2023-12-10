// Copyright 2023 The Inspektor Gadget authors
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

// Package kfilefields provides functions to read kernel "struct file" fields against a file descriptor.
//
// This is done:
//   - without using bpf iterators in order to work on old kernels.
//   - without comparing pids from userspace and ebpf in order to work from
//     different pid namespaces.
package kfilefields

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/btfgen"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -cc clang -cflags ${CFLAGS} -no-global-types filefields ./bpf/filefields.bpf.c -- -I./bpf/

type FdType int

const (
	FdTypeCustom FdType = iota
	FdTypeSocket
	FdTypeEbpfProgram
)

var supportedFdTypesForFOp = map[FdType]struct{}{
	FdTypeSocket:      {},
	FdTypeEbpfProgram: {},
}

func (fd FdType) String() string {
	switch fd {
	case FdTypeCustom:
		return "custom"
	case FdTypeSocket:
		return "socket"
	case FdTypeEbpfProgram:
		return "ebpf_program"
	default:
		return fmt.Sprintf("unknown(%d)", fd)
	}
}

type fileFields struct {
	PrivateData uint64
	FOp         uint64
}

// ReadPrivateDataFromFd uses ebpf to read the private_data pointer from the
// kernel "struct file" associated with the given fd.
func ReadPrivateDataFromFd(fd int) (uint64, error) {
	ff, err := readStructFileFields(FdTypeCustom, fd)
	if err != nil {
		return 0, fmt.Errorf("reading file fields: %w", err)
	}
	return ff.PrivateData, nil
}

// ReadFOpForFdType uses ebpf to read the f_op pointer from the kernel "struct file"
// associated with the given fd type.
func ReadFOpForFdType(kind FdType) (uint64, error) {
	if _, ok := supportedFdTypesForFOp[kind]; !ok {
		return 0, fmt.Errorf("unsupported fd type %s", kind.String())

	}
	ff, err := readStructFileFields(kind, -1)
	if err != nil {
		return 0, fmt.Errorf("reading file fields: %w", err)
	}
	return ff.FOp, nil
}

func readStructFileFields(kind FdType, fd int) (*fileFields, error) {
	var objs filefieldsObjects
	var links []link.Link
	var err error
	sock := [2]int{-1, -1}

	defer func() {
		for i := 0; i < 2; i++ {
			if sock[i] != -1 {
				unix.Close(sock[i])
			}
		}
		for _, l := range links {
			gadgets.CloseLink(l)
		}
		objs.Close()
	}()

	// Create a socket pair
	sock, err = unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		return nil, fmt.Errorf("creating socket pair: %w", err)
	}

	// Find the inode of the socket
	fdFileInfo, err := os.Stat(fmt.Sprintf("/proc/self/fd/%d", sock[0]))
	if err != nil {
		return nil, fmt.Errorf("reading file info from sock fd %d: %w", sock[0], err)
	}
	fdStat, ok := fdFileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, errors.New("not a syscall.Stat_t")
	}
	fdIno := fdStat.Ino

	// Load ebpf program configured with the socket inode
	spec, err := loadFilefields()
	if err != nil {
		return nil, fmt.Errorf("load ebpf program for container-hook: %w", err)
	}
	consts := map[string]interface{}{
		"socket_ino": uint64(fdIno),
	}
	if err := spec.RewriteConstants(consts); err != nil {
		return nil, fmt.Errorf("RewriteConstants: %w", err)
	}

	opts := ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			KernelTypes: btfgen.GetBTFSpec(),
		},
	}
	if err := spec.LoadAndAssign(&objs, &opts); err != nil {
		return nil, fmt.Errorf("loading maps and programs: %w", err)
	}

	// Attach ebpf programs
	l, err := link.Kprobe("__scm_send", objs.IgScmSndE, nil)
	if err != nil {
		return nil, fmt.Errorf("attaching kprobe __scm_send: %w", err)
	}
	links = append(links, l)

	l, err = link.Kretprobe("fget_raw", objs.IgFgetX, nil)
	if err != nil {
		return nil, fmt.Errorf("attaching kretprobe fget_raw: %w", err)
	}
	links = append(links, l)

	switch kind {
	case FdTypeCustom:
		// nothing to do
	case FdTypeSocket:
		fd = sock[0]
	case FdTypeEbpfProgram:
		fd = objs.IgFgetX.FD()
	default:
		return nil, fmt.Errorf("unknown fd type %d", kind)
	}

	// Send the fd through the socket with SCM_RIGHTS.
	// This will trigger the __scm_send kprobe and fget_raw kretprobe
	buf := make([]byte, 1)
	err = unix.Sendmsg(sock[0], buf, unix.UnixRights(fd), nil, 0)
	if err != nil {
		return nil, fmt.Errorf("sending fd: %w", err)
	}

	var ff fileFields
	err = objs.IgFileFields.Lookup(uint32(0), &ff)
	if err != nil {
		return nil, fmt.Errorf("reading file fields: %w", err)
	}

	return &ff, nil
}
