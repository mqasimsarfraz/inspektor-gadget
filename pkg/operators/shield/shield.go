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
	"fmt"
	"io"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/viper"
	"oras.land/oras-go/v2"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/shield"
)

type shieldOperator struct{}

func (*shieldOperator) Name() string { return "shield" }

func (*shieldOperator) InstantiateImageOperator(
	ctx operators.GadgetContext, target oras.ReadOnlyTarget, desc ocispec.Descriptor, values api.ParamValues,
) (operators.ImageOperatorInstance, error) {
	if ctx.IsClient() || ctx.IsRemoteCall() {
		return nil, fmt.Errorf("IG-Shield initially supports standalone local ig runs only")
	}
	if len(values) != 0 {
		return nil, fmt.Errorf("IG-Shield does not support runtime patch parameters")
	}
	if err := verifiedLayer(ctx, desc); err != nil {
		return nil, err
	}
	cfg, ok := ctx.GetVar("config")
	if !ok {
		return nil, fmt.Errorf("missing shield metadata")
	}
	v, ok := cfg.(*viper.Viper)
	if !ok || v.GetString("name") == "" || len(v.GetStringMap("datasources")) != 0 || len(v.GetStringMap("params")) != 0 || len(v.GetStringMap("programs")) != 0 {
		return nil, fmt.Errorf("shield metadata must be descriptive only, without datasources, params or program overrides")
	}
	if desc.Size <= 0 || desc.Size > shield.MaxPackageSize {
		return nil, fmt.Errorf("invalid shield package layer size %d", desc.Size)
	}
	if err := desc.Digest.Validate(); err != nil {
		return nil, fmt.Errorf("invalid shield layer digest: %w", err)
	}
	r, err := oci.GetContentFromDescriptor(ctx.Context(), target, desc)
	if err != nil {
		return nil, err
	}
	b, readErr := io.ReadAll(io.LimitReader(r, shield.MaxPackageSize+1))
	closeErr := r.Close()
	if readErr != nil {
		return nil, fmt.Errorf("reading shield package: %w", readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("closing shield package reader: %w", closeErr)
	}
	check := desc.Digest.Verifier()
	check.Write(b)
	if int64(len(b)) != desc.Size || !check.Verified() {
		return nil, fmt.Errorf("shield package bytes do not match the verified layer size/digest")
	}
	pkg, err := shield.ReadPackage(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	return &instance{pkg: pkg, desc: desc}, nil
}

func verifiedLayer(ctx operators.GadgetContext, desc ocispec.Descriptor) error {
	value, ok := ctx.GetVar(operators.VerifiedImageVar)
	proof, typed := value.(*operators.VerifiedImage)
	if !ok || !typed || proof == nil || proof.Reference == "" {
		return fmt.Errorf("IG-Shield requires verified OCI image provenance")
	}
	for _, layer := range proof.Layers {
		if layer.MediaType == desc.MediaType && layer.Digest == desc.Digest && layer.Size == desc.Size {
			return nil
		}
	}
	return fmt.Errorf("shield package layer is not part of the verified image")
}

type instance struct {
	pkg  *shield.Package
	desc ocispec.Descriptor
	run  *shield.Run
}

func (*instance) Name() string { return "shield" }

func (i *instance) Start(ctx operators.GadgetContext) error {
	if i.run != nil {
		return fmt.Errorf("shield package is already active")
	}
	if err := verifiedLayer(ctx, i.desc); err != nil {
		return err
	}
	run, err := shield.Load(ctx.Context(), i.pkg)
	if err != nil {
		return fmt.Errorf("applying shield package %q (owned attachments rolled back): %w", i.pkg.Name, err)
	}
	i.run = run
	for _, patch := range i.pkg.Patches {
		ctx.Logger().Infof("IG-Shield applied patch %s payload=%x", patch.Name, patch.Digest)
	}
	return nil
}

func (i *instance) Stop(ctx operators.GadgetContext) error {
	if i.run == nil {
		return nil
	}
	run := i.run
	i.run = nil
	if err := run.Close(); err != nil {
		return fmt.Errorf("removing shield package %q: %w", i.pkg.Name, err)
	}
	ctx.Logger().Infof("IG-Shield removed package %s", i.pkg.Name)
	return nil
}

func (i *instance) Close(ctx operators.GadgetContext) error { return i.Stop(ctx) }

func init() {
	operators.RegisterOperatorForMediaType(shield.MediaType, &shieldOperator{})
}
