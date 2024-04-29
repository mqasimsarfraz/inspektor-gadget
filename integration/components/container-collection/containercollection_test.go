// Copyright 2024 The Inspektor Gadget authors
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

package containercollection

import (
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	containerutilsTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/containers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestContainerCollectionRuntimeEnrichment(t *testing.T) {
	var allContainers []*containers.TestContainer
	registerCleanup(t, &allContainers)
	for i := 0; i < *containerCount; i++ {
		cn := "test_containercollection_runtimeenrichment_" + strconv.Itoa(i)
		c := containerFactory.NewContainer(cn, "sleep inf", containers.WithStartAndStop(), containers.WithContainerImage("mirror.gcr.io/library/busybox"))
		c.Start(t)
		allContainers = append(allContainers, c)
	}

	err := rlimit.RemoveMemlock()
	require.Nil(t, err)

	cc := containercollection.ContainerCollection{}
	rc := containerutilsTypes.RuntimeConfig{Name: types.String2RuntimeName(*runtime)}
	opts := []containercollection.ContainerCollectionOption{
		containercollection.WithContainerRuntimeEnrichment(&rc),
		containercollection.WithLinuxNamespaceEnrichment(),
	}
	err = cc.Initialize(opts...)
	require.Nil(t, err)

	// Check that all containers are in the collection
	for _, c := range allContainers {
		con := cc.GetContainer(c.ID())
		require.NotNil(t, con)
		require.Equal(t, c.ID(), con.Runtime.ContainerID)
	}
}

func registerCleanup(t *testing.T, allContainers *[]*containers.TestContainer) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigs
		for _, c := range *allContainers {
			c.Stop(t)
		}
		os.Exit(1)
	}()

	t.Cleanup(func() {
		for _, c := range *allContainers {
			c.Stop(t)
		}
	})
}
