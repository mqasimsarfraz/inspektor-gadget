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

package tests

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
)

const (
	sayHelloMethod = "/helloworld.Greeter/SayHello"
	serverDelay    = 100 * time.Millisecond
)

type grpcEvent struct {
	Method         string `json:"method"`
	TypeRaw        uint32 `json:"type_raw"`
	DecodedPayload string `json:"decoded_payload"`
	LatencyNSRaw   uint64 `json:"latency_ns_raw"`
	Failed         uint8  `json:"failed"`
}

func TestTraceGRPCLatency(t *testing.T) {
	gadgettesting.InitUnitTest(t)

	workloadDir, err := filepath.Abs("../workload")
	require.NoError(t, err)

	build := exec.Command("make", "-C", workloadDir, "clean", "all")
	require.NoError(t, build.Run())

	workloadPath := filepath.Join(workloadDir, "client")
	workload := exec.Command(workloadPath)
	workload.Stdout = io.Discard
	workload.Stderr = io.Discard
	require.NoError(t, workload.Start())

	t.Cleanup(func() {
		if workload.Process == nil {
			return
		}
		_ = workload.Process.Kill()
		_, _ = workload.Process.Wait()
	})

	time.Sleep(200 * time.Millisecond)

	image := gadgetrunner.GetGadgetImageName("trace_grpc")
	igPath, err := exec.LookPath("ig")
	require.NoError(t, err)

	var stderr bytes.Buffer
	run := exec.Command(igPath, "run", image,
		"--host",
		"--verify-image=false",
		"--pull=never",
		"--target-path="+workloadPath,
		"--timeout=4",
		"-o", "json",
	)
	run.Stderr = &stderr
	output, err := run.Output()
	require.NoError(t, err, stderr.String())

	events := make([]grpcEvent, 0)
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		var event grpcEvent
		require.NoError(t, json.Unmarshal(scanner.Bytes(), &event),
			fmt.Sprintf("unmarshalling event %q", scanner.Text()))
		events = append(events, event)
	}
	require.NoError(t, scanner.Err())

	var sendEvent, completionEvent *grpcEvent
	for i := range events {
		event := &events[i]
		if event.Method != sayHelloMethod {
			continue
		}
		switch event.TypeRaw {
		case 1:
			sendEvent = event
		case 2:
			completionEvent = event
		}
		if sendEvent != nil && completionEvent != nil {
			break
		}
	}

	require.NotNil(t, sendEvent, "expected a gRPC request event")
	require.Contains(t, sendEvent.DecodedPayload, `string("world")`)

	require.NotNil(t, completionEvent, "expected a gRPC completion event")
	require.GreaterOrEqual(t, time.Duration(completionEvent.LatencyNSRaw), serverDelay)
	require.Less(t, time.Duration(completionEvent.LatencyNSRaw), time.Second)
	require.Zero(t, completionEvent.Failed)
}
