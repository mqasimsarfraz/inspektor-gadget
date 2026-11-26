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

package shield

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"

	metadatav1 "github.com/inspektor-gadget/inspektor-gadget/pkg/metadata/v1"
)

func ValidateMetadata(b []byte) error {
	var meta metadatav1.GadgetMetadata
	decoder := yaml.NewDecoder(bytes.NewReader(b))
	decoder.KnownFields(true)
	if err := decoder.Decode(&meta); err != nil {
		return fmt.Errorf("shield metadata must contain descriptive fields only: %w", err)
	}
	if meta.Name == "" || len(meta.DataSources) != 0 || len(meta.Params) != 0 {
		return fmt.Errorf("shield metadata needs a name and must not declare datasources or params")
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err != nil {
			return fmt.Errorf("reading shield metadata: %w", err)
		}
		return fmt.Errorf("shield metadata must contain exactly one YAML document")
	}
	return nil
}
