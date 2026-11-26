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

package shieldoperator

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/memory"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/testing/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/shield"
)

type testContext struct {
	gadgetcontext.MockGadgetContext
	vars   map[string]any
	client bool
	remote bool
}

func (c *testContext) GetVar(key string) (any, bool) {
	v, ok := c.vars[key]
	return v, ok
}

func (c *testContext) IsClient() bool     { return c.client }
func (c *testContext) IsRemoteCall() bool { return c.remote }

type corruptTarget struct {
	oras.ReadOnlyTarget
}

func (c corruptTarget) Fetch(context.Context, ocispec.Descriptor) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader([]byte("corrupted bytes"))), nil
}

func TestInspectVerifiedPackage(t *testing.T) {
	b, err := os.ReadFile("../../shield/testdata/mitigation.bee")
	require.NoError(t, err)
	desc := ocispec.Descriptor{MediaType: shield.MediaType, Digest: digest.FromBytes(b), Size: int64(len(b))}
	target := memory.New()
	require.NoError(t, target.Push(context.Background(), desc, bytes.NewReader(b)))
	config := viper.New()
	config.Set("name", "mitigation")
	ctx := &testContext{
		MockGadgetContext: gadgetcontext.MockGadgetContext{Ctx: context.Background()},
		vars:              map[string]any{"config": config},
	}
	op := &shieldOperator{}
	_, err = op.InstantiateImageOperator(ctx, target, desc, nil)
	require.ErrorContains(t, err, "verified OCI image provenance")
	proof := &operators.VerifiedImage{Reference: "example.com/shield@sha256:verified", Layers: []ocispec.Descriptor{desc}}
	ctx.vars[operators.VerifiedImageVar] = proof
	instance, err := op.InstantiateImageOperator(ctx, target, desc, nil)
	require.NoError(t, err)
	require.NoError(t, instance.Close(ctx))
	_, err = op.InstantiateImageOperator(ctx, corruptTarget{target}, desc, nil)
	require.ErrorContains(t, err, "verified layer size/digest")
	_, err = op.InstantiateImageOperator(ctx, target, desc, api.ParamValues{"enabled": "true"})
	require.ErrorContains(t, err, "runtime patch parameters")
	ctx.client = true
	_, err = op.InstantiateImageOperator(ctx, target, desc, nil)
	require.ErrorContains(t, err, "standalone local")
	ctx.client = false
	ctx.remote = true
	_, err = op.InstantiateImageOperator(ctx, target, desc, nil)
	require.ErrorContains(t, err, "standalone local")
	ctx.remote = false
	// Inspection never needs kernel privileges; changing provenance also
	// prevents Start from reaching the kernel.
	proof.Layers = nil
	require.ErrorContains(t, instance.Start(ctx), "not part of the verified image")
	require.NoError(t, instance.Stop(ctx))
}
