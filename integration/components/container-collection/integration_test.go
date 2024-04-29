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
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/containers"
)

var (
	containerFactory containers.ContainerFactory
	// flags
	integration    = flag.Bool("integration", false, "run integration tests")
	runtime        = flag.String("runtime", "docker", "which runtime to use (docker, containerd)")
	containerCount = flag.Int("container-count", 10, "number of container to start")
)

func TestMain(m *testing.M) {
	flag.Parse()

	if !*integration {
		fmt.Println("Skipping image tests")
		os.Exit(0)
	}

	var err error
	containerFactory, err = containers.NewContainerFactory(*runtime)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}

	fmt.Println("Running image tests")
	os.Exit(m.Run())
}
