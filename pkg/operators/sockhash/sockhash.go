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

// Package sockhash provides a DataOperator that owns the framework side of the
// TCP-stream plumbing for gadgets that use include/gadget/tcp_stream.h.
//
// When a gadget references the shared SOCKHASH map, this operator creates a
// per-gadget producer (sock_ops + fexit/tcp_connect + maps, see pkg/sockhash),
// filtered to the ports the gadget asked for, and hands the resulting maps to
// the eBPF operator via gadget-context variables. The eBPF operator then injects
// them into the gadget collection through CollectionOptions.MapReplacements, so
// the gadget's sk_skb / sk_msg programs run on sockets selected and enriched by
// the framework. The producer (and the socket references its SOCKHASH holds) is
// torn down when the gadget stops.
package sockhash

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	tracer "github.com/inspektor-gadget/inspektor-gadget/pkg/sockhash"
)

const (
	OperatorName = "Sockhash"

	// ParamPorts is the comma-separated list of TCP ports the producer should
	// track. A gadget using tcp_stream.h sets its default via its operator
	// params in gadget.yaml; a user may override it at runtime.
	ParamPorts = "tcp-stream-ports"
)

type Sockhash struct{}

func (s *Sockhash) Name() string {
	return OperatorName
}

func (s *Sockhash) Description() string {
	return "Sockhash provides the framework-owned SOCKHASH producer for TCP-stream gadgets"
}

func (s *Sockhash) GlobalParams() api.Params {
	return nil
}

func (s *Sockhash) InstanceParams() api.Params {
	return api.Params{
		{
			Key:          ParamPorts,
			Title:        "TCP stream ports",
			Description:  "Comma-separated TCP ports to track for TCP-stream gadgets (e.g. \"53,80\"). A socket is tracked when either of its ports matches.",
			DefaultValue: "",
			TypeHint:     api.TypeString,
		},
	}
}

func (s *Sockhash) InstantiateDataOperator(gadgetCtx operators.GadgetContext, instanceParamValues api.ParamValues) (operators.DataOperatorInstance, error) {
	// Only activate when the gadget declares the shared SOCKHASH map. The eBPF
	// operator sets this variable (to a nil *ebpf.Map) while analyzing the
	// gadget, so its presence means the gadget expects the framework to provide
	// the producer and its maps.
	if _, ok := gadgetCtx.GetVar(tracer.MapName); !ok {
		return nil, nil
	}

	ports, err := parsePorts(instanceParamValues[ParamPorts])
	if err != nil {
		return nil, err
	}

	return &SockhashInstance{
		gadgetCtx: gadgetCtx,
		ports:     ports,
	}, nil
}

func (s *Sockhash) Priority() int {
	return 10
}

func (s *Sockhash) Init(*params.Params) error {
	return nil
}

func (s *Sockhash) Close() error {
	return nil
}

type SockhashInstance struct {
	gadgetCtx operators.GadgetContext
	ports     []uint16
	sockhash  *tracer.Sockhash
}

func (i *SockhashInstance) Name() string {
	return "SockhashInstance"
}

func (i *SockhashInstance) PreStart(gadgetCtx operators.GadgetContext) error {
	t, err := tracer.New(i.ports)
	if err != nil {
		return fmt.Errorf("creating sockhash producer: %w", err)
	}
	i.sockhash = t

	// Hand the framework-owned maps to the eBPF operator. It replaces the
	// gadget-declared maps with these instances via MapReplacements when it
	// loads the collection.
	i.gadgetCtx.Logger().Debugf("setting framework sockhash maps (ports=%v)", i.ports)
	i.gadgetCtx.SetVar(tracer.MapName, t.SockhashMap())
	i.gadgetCtx.SetVar(tracer.ConnsMapName, t.ConnsMap())
	i.gadgetCtx.SetVar(tracer.TuplesMapName, t.TuplesMap())
	return nil
}

func (i *SockhashInstance) Start(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (i *SockhashInstance) Stop(gadgetCtx operators.GadgetContext) error {
	if i.sockhash != nil {
		i.sockhash.Close()
		i.sockhash = nil
	}
	return nil
}

func (i *SockhashInstance) Close(gadgetCtx operators.GadgetContext) error {
	return nil
}

// parsePorts parses a comma-separated list of TCP ports.
func parsePorts(s string) ([]uint16, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}

	var ports []uint16
	for _, field := range strings.Split(s, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		port, err := strconv.ParseUint(field, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %w", field, err)
		}
		if port == 0 {
			return nil, fmt.Errorf("invalid port %q: must be 1-65535", field)
		}
		ports = append(ports, uint16(port))
	}
	return ports, nil
}

func init() {
	operators.RegisterDataOperator(&Sockhash{})
}
