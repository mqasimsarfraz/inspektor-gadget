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

// Package sockhash owns the framework side of the TCP-stream plumbing: the
// SOCKHASH and connection maps plus the sock_ops / fexit programs that populate
// them (see bpf/sockhash.bpf.c). Gadgets ship only the sk_skb / sk_msg
// consumers declared against these maps in include/gadget/tcp_stream.h; the
// framework creates a per-gadget instance here and injects the maps into the
// gadget collection via MapReplacements, so the lifecycle of the live socket
// references stays under framework control.
package sockhash

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/btfgen"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/cgroups"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -cc clang -cflags ${CFLAGS} sockhash ./bpf/sockhash.bpf.c -- -I./bpf/

const (
	// MapName is the SOCKHASH sk_skb / sk_msg programs are attached to.
	MapName = "gadget_sockhash"
	// ConnsMapName maps a socket cookie to its connection (sk_skb path).
	ConnsMapName = "gadget_tcp_stream_conns"
	// TuplesMapName maps a connection 4-tuple to its connection (sk_msg path).
	TuplesMapName = "gadget_tcp_stream_tuples"

	// MaxEntries is the number of sockets the SOCKHASH can hold. It must stay in
	// sync with the specs declared in include/gadget/tcp_stream.h so the two are
	// map-compatible for replacement.
	MaxEntries = 65536
)

// Sockhash owns a running instance of the framework producer: the maps and the
// sock_ops / fexit programs that populate them.
type Sockhash struct {
	objs  sockhashObjects
	links []link.Link
}

// New loads the framework producer, populates the tracked-ports filter with the
// given host-order ports, attaches the sock_ops program to the cgroup v2 root
// and the fexit/tcp_connect program, and returns a handle exposing the maps.
func New(ports []uint16) (*Sockhash, error) {
	s := &Sockhash{}
	if err := s.start(ports); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func (s *Sockhash) start(ports []uint16) error {
	spec, err := loadSockhash()
	if err != nil {
		return fmt.Errorf("loading sockhash asset: %w", err)
	}

	opts := ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			KernelTypes: btfgen.GetBTFSpec(),
		},
	}
	if err := spec.LoadAndAssign(&s.objs, &opts); err != nil {
		return fmt.Errorf("loading sockhash ebpf program: %w", err)
	}

	if err := s.setPorts(ports); err != nil {
		return err
	}

	cgroupPath, err := cgroups.CgroupPathV2AddMountpoint("/")
	if err != nil {
		return fmt.Errorf("resolving cgroup v2 root mountpoint: %w", err)
	}

	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: s.objs.GadgetTcpStreamSockops,
	})
	if err != nil {
		return fmt.Errorf("attaching sockops to cgroup %q: %w", cgroupPath, err)
	}
	s.links = append(s.links, l)

	l, err = link.AttachTracing(link.TracingOptions{
		Program: s.objs.GadgetTcpStreamConnect,
	})
	if err != nil {
		return fmt.Errorf("attaching fexit/tcp_connect: %w", err)
	}
	s.links = append(s.links, l)

	return nil
}

// setPorts populates the tracked-ports filter map. A socket is tracked when
// either of its ports is present here.
func (s *Sockhash) setPorts(ports []uint16) error {
	one := uint8(1)
	for _, port := range ports {
		if err := s.objs.GadgetTcpStreamPorts.Update(&port, &one, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("adding tracked port %d: %w", port, err)
		}
	}
	return nil
}

// SockhashMap returns the SOCKHASH map so sk_skb / sk_msg programs can be
// attached to it (via MapReplacements).
func (s *Sockhash) SockhashMap() *ebpf.Map {
	return s.objs.GadgetSockhash
}

// ConnsMap returns the cookie-indexed connection map read by the sk_skb path.
func (s *Sockhash) ConnsMap() *ebpf.Map {
	return s.objs.GadgetTcpStreamConns
}

// TuplesMap returns the tuple-indexed connection map read by the sk_msg path.
func (s *Sockhash) TuplesMap() *ebpf.Map {
	return s.objs.GadgetTcpStreamTuples
}

// Close detaches the producer programs and releases the maps, dropping the
// socket references the SOCKHASH holds.
func (s *Sockhash) Close() {
	for _, l := range s.links {
		gadgets.CloseLink(l)
	}
	s.links = nil
	s.objs.Close()
}
