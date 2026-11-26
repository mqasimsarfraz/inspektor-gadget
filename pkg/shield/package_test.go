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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func fixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/mitigation.bee")
	require.NoError(t, err)
	return b
}

func rewriteFixture(t *testing.T, mutate func(*tar.Header, []byte)) []byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(fixture(t)))
	require.NoError(t, err)
	defer gz.Close()
	tr := tar.NewReader(gz)
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	tw := tar.NewWriter(zw)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		b, err := io.ReadAll(tr)
		require.NoError(t, err)
		mutate(h, b)
		require.NoError(t, tw.WriteHeader(h))
		_, err = tw.Write(b)
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, zw.Close())
	return out.Bytes()
}

func TestReadPackage(t *testing.T) {
	pkg, err := ReadPackage(bytes.NewReader(fixture(t)))
	require.NoError(t, err)
	require.Equal(t, "ig-shield-probe-1.0.0", pkg.Name)
	require.Len(t, pkg.Patches, 1)
	require.Len(t, pkg.Patches[0].programs, 2)
	require.Equal(t, uint32(2), pkg.Patches[0].maps)
	require.ElementsMatch(t, []uint32{0, 5}, pkg.Patches[0].programs)
}

func TestReadPackageRejectsInvalidInput(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*tar.Header, []byte)
		error  string
	}{
		{"traversal", func(h *tar.Header, _ []byte) { h.Name = "root/../" + h.Name }, "unsafe bee member"},
		{"second-root", func(h *tar.Header, _ []byte) {
			if strings.HasSuffix(h.Name, "/cert.der") {
				h.Name = "other/cert.der"
			}
		}, "outside its package"},
		{"digest", func(h *tar.Header, b []byte) {
			if strings.HasSuffix(h.Name, ".upatch") {
				b[272] ^= 1
			}
		}, "digest mismatch"},
		{"java", func(h *tar.Header, b []byte) {
			if strings.HasSuffix(h.Name, ".upatch") {
				binary.LittleEndian.PutUint32(b[352:], 2)
			}
		}, "only BPF v1"},
		{"overlap", func(h *tar.Header, b []byte) {
			if strings.HasSuffix(h.Name, ".upatch") {
				copy(b[312:316], b[304:308])
			}
		}, "overlapping upatch"},
		{"missing-directive", func(h *tar.Header, _ []byte) {
			if strings.HasSuffix(h.Name, ".unload.upatch") {
				h.Name = strings.TrimSuffix(h.Name, ".upatch") + ".ignored"
			}
		}, "matching unload"},
		{"hidden-artifact", func(h *tar.Header, _ []byte) {
			if strings.HasSuffix(h.Name, ".upatch") {
				h.Name = strings.Replace(h.Name, "/upatches/", "/upatches/.", 1)
			}
		}, "visible file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ReadPackage(bytes.NewReader(rewriteFixture(t, tc.mutate)))
			require.ErrorContains(t, err, tc.error)
		})
	}
	_, err := ReadPackage(strings.NewReader("name: a-textual-Beefile"))
	require.ErrorContains(t, err, "built gzip .bee archive")
	_, err = ReadPackage(bytes.NewReader(append(fixture(t), 1)))
	require.ErrorContains(t, err, "trailing compressed data")
	b := fixture(t)
	_, err = ReadPackage(bytes.NewReader(b[:len(b)-8]))
	require.Error(t, err)
}

func TestValidateMetadata(t *testing.T) {
	require.NoError(t, ValidateMetadata([]byte("name: mitigation\ndescription: Blocks a vulnerable operation\n")))
	for _, b := range []string{
		"description: no-name",
		"name: mitigation\nparams:\n  enabled:\n    key: enabled",
		"name: mitigation\ndatasources:\n  events: {}",
		"name: mitigation\nprograms: {}",
		"name: mitigation\ncustomparams: []",
		"name: mitigation\n---\nname: replacement",
	} {
		require.Error(t, ValidateMetadata([]byte(b)), b)
	}
}

func TestArtifactRejectsUnsupportedExtensions(t *testing.T) {
	gz, err := gzip.NewReader(bytes.NewReader(fixture(t)))
	require.NoError(t, err)
	defer gz.Close()
	tr := tar.NewReader(gz)
	var artifact []byte
	for {
		h, err := tr.Next()
		require.NoError(t, err)
		if strings.HasSuffix(h.Name, "/program.upatch") {
			artifact, err = io.ReadAll(tr)
			require.NoError(t, err)
			break
		}
	}
	le := binary.LittleEndian
	for _, tc := range []struct {
		name string
		tag  uint32
		off  int
		val  uint32
		err  string
	}{
		{"serializer", 0x4d475055, 16, 1, "unsupported program"},
		{"other-attach", 0x4d475055, 20, 2, "unsupported program"},
		{"policy", 0x4d475055, -1, 0x4c504853, "unsupported upatch section"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := bytes.Clone(artifact)
			data := b[le.Uint32(b[328:]):][:le.Uint32(b[332:])]
			trailer := data[len(data)-16:]
			dir, count := le.Uint32(trailer[8:]), le.Uint32(trailer[12:])
			for idx := range count {
				entry := data[dir+16*idx:]
				if le.Uint32(entry) != tc.tag {
					continue
				}
				if tc.off < 0 {
					le.PutUint32(entry, tc.val)
				} else {
					start := le.Uint32(entry[8:])
					le.PutUint32(data[int(start)+tc.off:], tc.val)
				}
			}
			hash := sha256.New()
			hash.Write(b[le.Uint32(b[304:]):][:le.Uint32(b[308:])])
			hash.Write(data)
			copy(b[272:304], hash.Sum(nil))
			_, err := parseArtifact(b)
			require.ErrorContains(t, err, tc.err)
		})
	}
}

func FuzzReadPackage(f *testing.F) {
	b, err := os.ReadFile("testdata/mitigation.bee")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	f.Add([]byte("name: recipe"))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ReadPackage(bytes.NewReader(b))
	})
}
