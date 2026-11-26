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
	"fmt"
	"io"
	"path"
	"slices"
	"strings"
)

const (
	MediaType       = "application/vnd.gadget.shield.package.v1+gzip"
	MaxArtifactSize = 16 << 20
	maxMembers      = 4096
	maxContentSize  = 256 << 20
	// Allow tar headers, padding and gzip overhead in addition to package content.
	MaxPackageSize = maxContentSize + maxMembers*1024 + (1 << 20)
)

type Package struct {
	Name    string
	Patches []*Patch
}

type Patch struct {
	Name     string
	Digest   [32]byte
	loader   []byte
	data     []byte
	maps     uint32
	programs []uint32
	unload   bool
	target   [32]byte
}

// ReadPackage validates a built .bee archive without executing its contents.
func ReadPackage(r io.Reader) (*Package, error) {
	compressed, err := io.ReadAll(io.LimitReader(r, MaxPackageSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading bee package: %w", err)
	}
	if len(compressed) > MaxPackageSize {
		return nil, fmt.Errorf("bee package exceeds %d bytes", MaxPackageSize)
	}
	if len(compressed) < 2 || compressed[0] != 0x1f || compressed[1] != 0x8b {
		return nil, fmt.Errorf("expected a built gzip .bee archive, not a textual Beefile or ELF; build the package with shirudo bpm build first")
	}
	input := bytes.NewReader(compressed)
	gz, err := gzip.NewReader(input)
	if err != nil {
		return nil, fmt.Errorf("opening bee gzip: %w", err)
	}
	defer gz.Close()
	gz.Multistream(false)
	expanded := &io.LimitedReader{R: gz, N: MaxPackageSize + 1}
	tr := tar.NewReader(expanded)
	pkg := &Package{}
	members := make(map[string]byte)
	artifacts := make(map[string]*Patch)
	var total int64
	for count := 0; ; count++ {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading bee tar header: %w", err)
		}
		if count >= maxMembers || h.Size < 0 || h.Size > maxContentSize-total {
			return nil, fmt.Errorf("bee exceeds member or content limits")
		}
		total += h.Size
		name := strings.TrimSuffix(h.Name, "/")
		if h.Format != tar.FormatUSTAR || h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeDir {
			return nil, fmt.Errorf("bee member %q must be a ustar regular file or directory", h.Name)
		}
		if h.Typeflag == tar.TypeDir && h.Size != 0 {
			return nil, fmt.Errorf("bee directory %q contains file data", h.Name)
		}
		for _, part := range strings.Split(name, "/") {
			if part == "" || part == "." || part == ".." {
				return nil, fmt.Errorf("unsafe bee member %q", h.Name)
			}
		}
		root, rel, nested := strings.Cut(name, "/")
		if pkg.Name == "" {
			pkg.Name = root
		}
		if root != pkg.Name || !nested && h.Typeflag != tar.TypeDir {
			return nil, fmt.Errorf("bee member %q is outside its package directory", h.Name)
		}
		if _, exists := members[name]; exists {
			return nil, fmt.Errorf("duplicate bee member %q", h.Name)
		}
		members[name] = h.Typeflag
		if h.Typeflag != tar.TypeReg || !strings.HasSuffix(rel, ".upatch") {
			continue
		}
		if path.Dir(rel) != "upatches" || strings.HasPrefix(path.Base(rel), ".") {
			return nil, fmt.Errorf("artifact %q must be a visible file directly in upatches/", h.Name)
		}
		if h.Size > MaxArtifactSize {
			return nil, fmt.Errorf("artifact %q exceeds %d bytes", h.Name, MaxArtifactSize)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("reading artifact %q: %w", h.Name, err)
		}
		p, err := parseArtifact(b)
		if err != nil {
			return nil, fmt.Errorf("artifact %q: %w", h.Name, err)
		}
		if p.unload != strings.HasSuffix(rel, ".unload.upatch") {
			return nil, fmt.Errorf("artifact %q has inconsistent load/unload type", h.Name)
		}
		artifacts[path.Base(rel)] = p
	}
	tail, err := io.ReadAll(expanded)
	if err != nil {
		return nil, fmt.Errorf("finishing bee gzip: %w", err)
	}
	if expanded.N == 0 || input.Len() != 0 {
		return nil, fmt.Errorf("bee has excessive expansion or trailing compressed data")
	}
	for _, b := range tail {
		if b != 0 {
			return nil, fmt.Errorf("bee has trailing data after tar end")
		}
	}
	if members[pkg.Name+"/Beefile"] != tar.TypeReg || members[pkg.Name+"/cert.der"] != tar.TypeReg {
		return nil, fmt.Errorf("bee is missing Beefile or cert.der")
	}
	names := make([]string, 0, len(artifacts))
	for name, p := range artifacts {
		if !p.unload {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	identities := make(map[string]bool)
	for _, name := range names {
		p := artifacts[name]
		directive := artifacts[strings.TrimSuffix(name, ".upatch")+".unload.upatch"]
		if directive == nil || directive.Name != p.Name || directive.target != p.Digest {
			return nil, fmt.Errorf("patch %q has no matching unload directive", name)
		}
		if identities[p.Name] {
			return nil, fmt.Errorf("duplicate patch identity %q", p.Name)
		}
		identities[p.Name] = true
		pkg.Patches = append(pkg.Patches, p)
	}
	if len(pkg.Patches) == 0 || len(artifacts) != 2*len(pkg.Patches) {
		return nil, fmt.Errorf("bee must contain paired load/unload artifacts")
	}
	return pkg, nil
}

func parseArtifact(b []byte) (*Patch, error) {
	if len(b) < 360 || len(b) > MaxArtifactSize {
		return nil, fmt.Errorf("invalid upatch size")
	}
	le := binary.LittleEndian
	u32 := func(off int) uint32 { return le.Uint32(b[off:]) }
	if le.Uint64(b) != 0x53485244554e4150 || u32(8) != 1 || u32(12) & ^uint32(1) != 0 || u32(352) != 1 || u32(356) != 0 {
		return nil, fmt.Errorf("unsupported upatch magic, version, flags or payload type (only BPF v1 is supported)")
	}
	nameBytes := b[16:272]
	nul := bytes.IndexByte(nameBytes, 0)
	if nul <= 0 {
		return nil, fmt.Errorf("invalid upatch name")
	}
	for _, c := range nameBytes[nul:] {
		if c != 0 {
			return nil, fmt.Errorf("nonzero upatch name padding")
		}
	}
	name := string(nameBytes[:nul])
	if strings.HasPrefix(name, ".") || len(strings.ReplaceAll(name, ".", "~d")) > 255 {
		return nil, fmt.Errorf("unsafe upatch name %q", name)
	}
	for _, c := range name {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && !strings.ContainsRune("._-", c) {
			return nil, fmt.Errorf("unsafe upatch name %q", name)
		}
	}
	type region struct{ start, end uint64 }
	var regions []region
	section := func(off int) ([]byte, error) {
		start, size := uint64(u32(off)), uint64(u32(off+4))
		end := start + size
		if start < 360 || size == 0 || end > uint64(len(b)) {
			return nil, fmt.Errorf("invalid upatch region at header offset %d", off)
		}
		for _, r := range regions {
			if start < r.end && end > r.start {
				return nil, fmt.Errorf("overlapping upatch regions")
			}
		}
		regions = append(regions, region{start, end})
		return b[start:end], nil
	}
	loader, err := section(304)
	if err != nil {
		return nil, err
	}
	if u32(304)%8 != 0 || len(loader)%8 != 0 {
		return nil, fmt.Errorf("unaligned loader instructions")
	}
	if _, err := section(312); err != nil {
		return nil, err
	}
	if u32(320) != 0 || u32(324) != 0 {
		return nil, fmt.Errorf("unsupported legacy metadata region")
	}
	data, err := section(328)
	if err != nil {
		return nil, err
	}
	if u32(348)%8 != 0 || uint64(u32(348)) > uint64(len(data)) {
		return nil, fmt.Errorf("invalid rodata offset")
	}
	p := &Patch{Name: name, loader: loader, data: data, maps: u32(340), unload: u32(12)&1 != 0}
	copy(p.Digest[:], b[272:304])
	hash := sha256.New()
	hash.Write(loader)
	hash.Write(data)
	if !bytes.Equal(hash.Sum(nil), p.Digest[:]) {
		return nil, fmt.Errorf("upatch payload digest mismatch")
	}
	nrProgs := u32(344)
	if p.maps > 64 || nrProgs == 0 || uint64(24)+16*uint64(p.maps)+4*uint64(nrProgs)+1024 > 65535 {
		return nil, fmt.Errorf("invalid loader map/program counts")
	}
	if len(data) < 16 {
		return nil, fmt.Errorf("missing upatch section trailer")
	}
	trailer := data[len(data)-16:]
	dir, count := uint64(le.Uint32(trailer[8:])), uint64(le.Uint32(trailer[12:]))
	if le.Uint32(trailer) != 0x52544753 || le.Uint32(trailer[4:]) != 1 || count == 0 || count > 8 || dir%8 != 0 || dir+16*count != uint64(len(data)-16) {
		return nil, fmt.Errorf("invalid upatch section directory")
	}
	sections := make(map[uint32][]byte)
	var spans []region
	for idx := uint64(0); idx < count; idx++ {
		entry := data[dir+16*idx : dir+16*(idx+1)]
		tag := le.Uint32(entry)
		start, size := uint64(le.Uint32(entry[8:])), uint64(le.Uint32(entry[12:]))
		if le.Uint32(entry[4:]) != 0 || start%8 != 0 || size == 0 || start+size > dir || sections[tag] != nil {
			return nil, fmt.Errorf("invalid or duplicate upatch section")
		}
		for _, span := range spans {
			if start < span.end && start+size > span.start {
				return nil, fmt.Errorf("overlapping upatch sections")
			}
		}
		spans = append(spans, region{start, start + size})
		sections[tag] = data[start : start+size]
		switch tag {
		case 0x454d414e, 0x4d475055, 0x444c4e55, 0x50595450:
		default:
			return nil, fmt.Errorf("unsupported upatch section %#x (policy, decoders and other extensions are not supported)", tag)
		}
	}
	if !bytes.Equal(sections[0x454d414e], nameBytes) {
		return nil, fmt.Errorf("upatch section/header name mismatch")
	}
	if typ := sections[0x50595450]; typ != nil && (len(typ) != 4 || le.Uint32(typ) != 1) {
		return nil, fmt.Errorf("unsupported payload type section")
	}
	if p.unload {
		target := sections[0x444c4e55]
		if len(target) != 32 || sections[0x4d475055] != nil {
			return nil, fmt.Errorf("invalid unload sections")
		}
		copy(p.target[:], target)
		return p, nil
	}
	meta := sections[0x4d475055]
	if sections[0x444c4e55] != nil || len(meta) != 16+160*int(nrProgs) || le.Uint32(meta) != 0x4d475055 || le.Uint32(meta[4:]) != 1 || le.Uint32(meta[8:]) != nrProgs || le.Uint32(meta[12:]) != p.maps {
		return nil, fmt.Errorf("invalid program attachment metadata")
	}
	for idx := uint32(0); idx < nrProgs; idx++ {
		entry := meta[16+160*idx : 16+160*(idx+1)]
		role, kind := le.Uint32(entry), le.Uint32(entry[4:])
		if role != 0 || kind != 0 && kind != 5 || le.Uint64(entry[8:]) != 0 {
			return nil, fmt.Errorf("unsupported program %d role %d or attachment kind %d; only LSM/fmod_ret attach programs are supported", idx, role, kind)
		}
		p.programs = append(p.programs, kind)
	}
	return p, nil
}
