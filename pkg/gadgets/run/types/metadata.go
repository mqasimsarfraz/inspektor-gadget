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

package types

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/hashicorp/go-multierror"
)

type Alignment string

const (
	AlignmenNone   Alignment = ""
	AlignmentLeft  Alignment = "left"
	AlignmentRight Alignment = "right"
)

type EllipsisType string

const (
	EllipsisNone   EllipsisType = ""
	EllipsisStart  EllipsisType = "start"
	EllipsisMiddle EllipsisType = "middle"
	EllipsisEnd    EllipsisType = "end"
)

// FieldAttributes describes how to format a field.
// Almost 1:1 mapping with columns.Attributes.
// TODO: Better to use columns.Attributes directly?
type FieldAttributes struct {
	Width     uint         `yaml:"width,omitempty"`
	MinWidth  uint         `yaml:"minWidth,omitempty"`
	MaxWidth  uint         `yaml:"maxWidth,omitempty"`
	Alignment Alignment    `yaml:"alignment,omitempty"`
	Hidden    bool         `yaml:"hidden,omitempty"`
	Ellipsis  EllipsisType `yaml:"ellipsis,omitempty"`
	Template  string       `yaml:"template,omitempty"`
}

type Field struct {
	Name        string                 `yaml:"name"`
	Description string                 `yaml:"description,omitempty"`
	Attributes  FieldAttributes        `yaml:"attributes"`
	Annotations map[string]interface{} `yaml:"annotations,omitempty"`
}
type Struct struct {
	Fields []Field `yaml:"fields"`
}

type Tracer struct {
	MapName    string `yaml:"mapName"`
	StructName string `yaml:"structName"`
}

type GadgetMetadata struct {
	Name        string            `yaml:"name"`
	Description string            `yaml:"description,omitempty"`
	Tracers     map[string]Tracer `yaml:"tracers,omitempty"`
	Structs     map[string]Struct `yaml:"structs,omitempty"`
}

func (m *GadgetMetadata) Validate(spec *ebpf.CollectionSpec) error {
	var result error

	if m.Name == "" {
		result = multierror.Append(result, errors.New("gadget name is required"))
	}

	if err := m.validateTracers(spec); err != nil {
		result = multierror.Append(result, err)
	}

	if err := m.validateStructs(spec); err != nil {
		result = multierror.Append(result, err)
	}

	return result
}

func (m *GadgetMetadata) validateTracers(spec *ebpf.CollectionSpec) error {
	var result error

	// Temporal limitation
	if len(m.Tracers) > 1 {
		result = multierror.Append(result, errors.New("only one tracer is allowed"))
	}

	for name, tracer := range m.Tracers {
		if tracer.MapName == "" {
			result = multierror.Append(result, fmt.Errorf("tracer %q is missing mapName", name))
		}

		if tracer.StructName == "" {
			result = multierror.Append(result, fmt.Errorf("tracer %q is missing structName", name))
		}

		_, ok := m.Structs[tracer.StructName]
		if !ok {
			result = multierror.Append(result, fmt.Errorf("tracer %q references unknown struct %q", name, tracer.StructName))
		}

		ebpfm, ok := spec.Maps[tracer.MapName]
		if !ok {
			result = multierror.Append(result, fmt.Errorf("map %q not found in eBPF object", tracer.MapName))
			continue
		}

		if ebpfm.Type != ebpf.RingBuf && ebpfm.Type != ebpf.PerfEventArray {
			err := fmt.Errorf("map %q has a wrong type, expected: ringbuf or perf event array, got: %s", tracer.MapName, ebpfm.Type.String())
			result = multierror.Append(result, err)
			continue
		}

		if ebpfm.Value == nil {
			result = multierror.Append(result, fmt.Errorf("map %q does not have BTF information its value", tracer.MapName))
			continue
		}

		if _, ok := ebpfm.Value.(*btf.Struct); !ok {
			result = multierror.Append(result, fmt.Errorf("value of BPF map %q is not a structure", tracer.MapName))
		}
	}

	return result
}

func (m *GadgetMetadata) validateStructs(spec *ebpf.CollectionSpec) error {
	var result error

	for name, mapStruct := range m.Structs {
		var btfStruct *btf.Struct
		if err := spec.Types.TypeByName(name, &btfStruct); err != nil {
			result = multierror.Append(result, fmt.Errorf("looking for struct %q in eBPF object: %w", name, err))
			continue
		}

		mapStructFields := make(map[string]Field, len(mapStruct.Fields))
		for _, f := range mapStruct.Fields {
			mapStructFields[f.Name] = f
		}

		btfStructFields := make(map[string]btf.Member, len(btfStruct.Members))
		for _, m := range btfStruct.Members {
			btfStructFields[m.Name] = m
		}

		for fieldName := range mapStructFields {
			if _, ok := btfStructFields[fieldName]; !ok {
				result = multierror.Append(result, fmt.Errorf("field %q not found in eBPF struct %q", fieldName, name))
			}
		}
	}

	return result
}
