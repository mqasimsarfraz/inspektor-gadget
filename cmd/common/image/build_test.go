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

package image

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestShieldBuildRejectsUnsafeConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config string
		error  string
		update bool
	}{
		{"missing-package", "shield: {}", "shield.package must name", false},
		{"source", "ebpfsource: patch.bpf.c\nshield:\n  package: patch.bee", "cannot use eBPF/WASM", false},
		{"wasm", "wasm: program.wasm\nshield:\n  package: patch.bee", "cannot use eBPF/WASM", false},
		{"generation", "shield:\n  package: patch.bee", "metadata generation", true},
		{"escape", "ebpfsource: \"\"\nshield:\n  package: ../patch.bee", "shield.package:", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			buildFile := filepath.Join(dir, "build.yaml")
			require.NoError(t, os.WriteFile(buildFile, []byte(tc.config), 0o600))
			opts := &cmdOpts{path: dir, file: buildFile, fileChanged: true, updateMetadata: tc.update}
			require.ErrorContains(t, runBuild(&cobra.Command{}, opts), tc.error)
		})
	}
}
