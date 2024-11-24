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

package tests

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	ebpftypes "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

type ExpectedFsnotifyEvent struct {
	Timestamp string `json:"timestamp"`

	Type string `json:"type"`

	TraceeProc ebpftypes.Process `json:"tracee_proc"`
	TracerProc ebpftypes.Process `json:"tracer_proc"`

	TraceeMntnsId uint64 `json:"tracee_mntns_id"`
	TracerMntnsId uint64 `json:"tracer_mntns_id"`

	TraceeUId uint32 `json:"tracee_uid"`
	TraceeGId uint32 `json:"tracee_gid"`
	TracerUId uint32 `json:"tracer_uid"`
	TracerGId uint32 `json:"tracer_gid"`

	Prio uint32 `json:"prio"`
	
	FaMask uint32 `json:"fa_mask"`
	IMask  uint32 `json:"i_mask"`

	FaType     string `json:"fa_type"`
	FaPId      uint32 `json:"fa_pid"`
	FaFlags    uint32 `json:"fa_flags"`
	FaFFlags   uint32 `json:"fa_f_flags"`
	FaResponse string `json:"fa_response"`

	IWd int32 `json:"i_wd"`
	ICookie uint32 `json:"i_cookie"`
	IIno uint32 `json:"i_ino"`
	IInoDir uint32 `json:"i_ino_dir"`

	Name string `json:"name"`
}

func (e ExpectedFsnotifyEvent) Print() {
	fmt.Printf("Timestamp: %s\n", e.Timestamp)
	fmt.Printf("Type: %s\n", e.Type)
	fmt.Printf("TraceeMntnsId: %d\n", e.TraceeMntnsId)
	fmt.Printf("TracerMntnsId: %d\n", e.TracerMntnsId)
	fmt.Printf("TraceeUId: %d\n", e.TraceeUId)
	fmt.Printf("TraceeGId: %d\n", e.TraceeGId)
	fmt.Printf("TracerUId: %d\n", e.TracerUId)
	fmt.Printf("TracerGId: %d\n", e.TracerGId)
	fmt.Printf("Prio: %d\n", e.Prio)
	fmt.Printf("FaMask: %d\n", e.FaMask)
	fmt.Printf("IMask: %d\n", e.IMask)
	fmt.Printf("FaType: %s\n", e.FaType)
	fmt.Printf("FaPId: %d\n", e.FaPId)
	fmt.Printf("FaFlags: %d\n", e.FaFlags)
	fmt.Printf("FaFFlags: %d\n", e.FaFFlags)
	fmt.Printf("FaResponse: %s\n", e.FaResponse)
	fmt.Printf("IWd: %d\n", e.IWd)
	fmt.Printf("ICookie: %d\n", e.ICookie)
	fmt.Printf("IIno: %d\n", e.IIno)
	fmt.Printf("IInoDir: %d\n", e.IInoDir)
	fmt.Printf("Name: %s\n", e.Name)
}

type testDef struct {
	runnerConfig   *utilstest.RunnerConfig
	generateEvent  func() (string, error)
	validateEvent  func(t *testing.T, info *utilstest.RunnerInfo, filepath string, events []ExpectedFsnotifyEvent)
}

func TestFsnotifyGadget(t *testing.T) {
	gadgettesting.InitUnitTest(t)
	runnerConfig := &utilstest.RunnerConfig{}

	testCases := map[string]testDef{
		"captures_events_with_filter": {
			runnerConfig:  runnerConfig,
			generateEvent: generateEvent,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, filepath string, events []ExpectedFsnotifyEvent) {

				for _, event := range events {
					event.Print()
				}

				// utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, pid int) *ExpectedFsnotifyEvent {
				// 	return &ExpectedFsnotifyEvent{
				// 		Timestamp: utils.NormalizedStr,

				// 		Type:  "inotify",
				// 		IMask: 134217736, // 134217736 = 0x08000008 = FS_CLOSE_WRITE | FS_EVENT_ON_CHILD
				// 		Name:  filepath,
				// 	}
				// })(t, info, 0, events)
			},
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var filepath string
			runner := utilstest.NewRunnerWithTest(t, testCase.runnerConfig)

			normalizeEvent := func(event *ExpectedFsnotifyEvent) {
				utils.NormalizeString(&event.Timestamp)

			}
			onGadgetRun := func(gadgetCtx operators.GadgetContext) error {
				utilstest.RunWithRunner(t, runner, func() error {
					var err error
					filepath, err = testCase.generateEvent()
					if err != nil {
						return err
					}
					return nil
				})
				return nil
			}
			opts := gadgetrunner.GadgetRunnerOpts[ExpectedFsnotifyEvent]{
				Image:          "fsnotify",
				Timeout:        5 * time.Second,
				OnGadgetRun:    onGadgetRun,
				NormalizeEvent: normalizeEvent,
			}

			gadgetRunner := gadgetrunner.NewGadgetRunner(t, opts)

			gadgetRunner.RunGadget()

			testCase.validateEvent(t, runner.Info, filepath, gadgetRunner.CapturedEvents)
		})
	}
}

func generateEvent() (string, error) {
	cmd := exec.Command("inotifywatch", "/tmp/")
	err := cmd.Start()
	if err != nil {
		return nil, err
	}

	touchCmd := exec.Command("touch", "/tmp/ABCDE")
	err = touchCmd.Run()
	if err != nil {
		return nil, err
	}

	return "ABCDE", nil
}
