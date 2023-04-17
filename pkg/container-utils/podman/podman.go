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

package podman

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/containers/podman/v4/pkg/bindings"
	"github.com/containers/podman/v4/pkg/bindings/containers"
	log "github.com/sirupsen/logrus"

	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
)

type PodmanClient struct {
	conn       context.Context
	socketPath string
}

func NewPodmanClient(socketPath string) (runtimeclient.ContainerRuntimeClient, error) {
	if socketPath == "" {
		socketPath = runtimeclient.PodmanDefaultSocketPath
	}

	conn, err := bindings.NewConnection(context.Background(), filepath.Join("unix://", socketPath))
	if err != nil {
		return nil, fmt.Errorf("error creating connection: %w", err)
	}

	return &PodmanClient{
		conn:       conn,
		socketPath: socketPath,
	}, nil
}

func (p PodmanClient) listContainers(filterContainer string) ([]*runtimeclient.ContainerData, error) {
	filters := make(map[string][]string)
	if filterContainer != "" {
		filters["id"] = []string{filterContainer}
	}
	ctrs, err := containers.List(p.conn, &containers.ListOptions{Filters: filters})
	if err != nil {
		return nil, fmt.Errorf("error listing containers via podman: %w", err)
	}

	ret := make([]*runtimeclient.ContainerData, len(ctrs))
	for i, c := range ctrs {
		ret[i] = &runtimeclient.ContainerData{
			ID:      c.ID,
			Name:    c.Names[0],
			State:   c.State,
			Runtime: runtimeclient.PodmanName,
		}
	}
	return ret, nil
}

func (p PodmanClient) GetContainers() ([]*runtimeclient.ContainerData, error) {
	ctrs, err := p.listContainers("")
	if err != nil {
		return nil, err
	}
	return ctrs, nil
}

func (p PodmanClient) GetContainer(containerID string) (*runtimeclient.ContainerData, error) {
	ctrs, err := p.listContainers(containerID)
	if err != nil {
		return nil, fmt.Errorf("error listing containers: %w", err)
	}
	if len(ctrs) == 0 {
		return nil, fmt.Errorf("container %q not found", containerID)
	}
	if len(ctrs) > 1 {
		log.Warnf("PodmanClient: multiple containers (%d) with ID %q. Taking the first one: %+v",
			len(ctrs), containerID, ctrs)
	}
	return ctrs[0], nil
}

func (p PodmanClient) GetContainerDetails(containerID string) (*runtimeclient.ContainerDetailsData, error) {
	c, err := containers.Inspect(p.conn, containerID, nil)
	if err != nil {
		return nil, fmt.Errorf("error inspecting container %q: %w", containerID, err)
	}

	return &runtimeclient.ContainerDetailsData{
		ContainerData: runtimeclient.ContainerData{
			ID:      c.ID,
			Name:    c.Name,
			State:   c.State.Status,
			Runtime: runtimeclient.PodmanName,
		},
		Pid:         c.State.Pid,
		CgroupsPath: c.State.CgroupPath,
	}, nil
}

func (p PodmanClient) Close() error {
	return nil
}
