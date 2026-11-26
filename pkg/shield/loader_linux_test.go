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
	"errors"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

type testCloser struct {
	id    int
	order *[]int
	err   error
}

func (c testCloser) Close() error {
	*c.order = append(*c.order, c.id)
	return c.err
}

func TestRunClose(t *testing.T) {
	var order []int
	failure := errors.New("cleanup failed")
	r := &Run{closers: []io.Closer{testCloser{1, &order, nil}, testCloser{2, &order, failure}, testCloser{3, &order, nil}}}
	require.ErrorIs(t, r.Close(), failure)
	require.Equal(t, []int{3, 2, 1}, order)
	require.NoError(t, r.Close())
	require.Equal(t, []int{3, 2, 1}, order)
}

func TestLoadCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, err := Load(ctx, &Package{Patches: []*Patch{{Name: "never-loaded"}}})
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, r)
}

func TestMitigationsVM(t *testing.T) {
	if os.Getenv("IG_SHIELD_TEST_VM") != "1" {
		t.Skip("requires a disposable VM; never enable on a shared host")
	}
	cmdline, err := os.ReadFile("/proc/cmdline")
	require.NoError(t, err)
	require.Contains(t, string(cmdline), "ig_shield_test_vm")
	pkg, err := ReadPackage(bytes.NewReader(fixture(t)))
	require.NoError(t, err)
	check := func(blocked bool) {
		t.Helper()
		fd, socketErr := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
		if socketErr == nil {
			require.NoError(t, unix.Close(fd))
		}
		_, pgidErr := unix.Getpgid(0)
		if blocked {
			require.ErrorIs(t, socketErr, unix.EPERM)
			require.ErrorIs(t, pgidErr, unix.EPERM)
		} else {
			require.NoError(t, socketErr)
			require.NoError(t, pgidErr)
		}
	}
	fdCount := func() int {
		t.Helper()
		fds, err := os.ReadDir("/proc/self/fd")
		require.NoError(t, err)
		return len(fds)
	}
	check(false)
	baseline := fdCount()
	run, err := Load(context.Background(), pkg)
	require.NoError(t, err)
	check(true)
	require.NoError(t, run.Close())
	require.NoError(t, run.Close())
	check(false)
	require.Equal(t, baseline, fdCount(), "all returned and loader FDs must be released")

	// A second patch loads successfully but disagrees with its declared
	// attachment type. Its failure must also remove the first patch's hooks.
	bad := *pkg.Patches[0]
	bad.Name = "second-patch"
	bad.programs = []uint32{5, 5}
	failed, err := Load(context.Background(), &Package{Patches: []*Patch{pkg.Patches[0], &bad}})
	require.ErrorContains(t, err, "second-patch")
	require.Nil(t, failed)
	check(false)
	require.Equal(t, baseline, fdCount(), "failed startup must not leak FDs")

	first, err := Load(context.Background(), pkg)
	require.NoError(t, err)
	second, err := Load(context.Background(), pkg)
	require.NoError(t, err)
	require.NoError(t, first.Close())
	check(true)
	require.NoError(t, second.Close())
	check(false)
	require.Equal(t, baseline, fdCount())
}
