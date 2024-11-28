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
	"fmt"
	"os/exec"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"

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

	IWd     int32  `json:"i_wd"`
	ICookie uint32 `json:"i_cookie"`
	IIno    uint32 `json:"i_ino"`
	IInoDir uint32 `json:"i_ino_dir"`

	Name string `json:"name"`
}

func (e ExpectedFsnotifyEvent) Print() {
	fmt.Printf("Timestamp: %s\n", e.Timestamp)
	fmt.Printf("Type: %s\n", e.Type)
	fmt.Printf("TraceeCommand: %s\n", e.TraceeProc.Comm)
	fmt.Printf("TracerCommand: %s\n", e.TracerProc.Comm)
	fmt.Printf("TraceeUid: %d\n", e.TraceeProc.Creds.Uid)
	fmt.Printf("TracerGid: %d\n", e.TracerProc.Creds.Gid)
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
	runnerConfig  *utilstest.RunnerConfig
	generateEvent func() (string, error)
	validateEvent func(t *testing.T, info *utilstest.RunnerInfo, filename string, events []ExpectedFsnotifyEvent)
}

func TestFsnotifyGadget(t *testing.T) {
	gadgettesting.InitUnitTest(t)
	runnerConfig := &utilstest.RunnerConfig{}

	testCases := map[string]testDef{
		"captures_inotify_event": {
			runnerConfig:  runnerConfig,
			generateEvent: generateEvent,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, filename string, events []ExpectedFsnotifyEvent) {

				fmt.Printf("--------------------------------------------------\n")
				fmt.Printf("YOU ARE LOOKING FOR THIS SECTION\n")
				fmt.Printf("--------------------------------------------------\n")
				for _, event := range events {
					event.Print()
					fmt.Printf("--------------------------------------------------\n")
				}

				fmt.Printf("runnerInfo proc command: %s\n", info.Proc.Comm)
				fmt.Printf("runnerInfo proc pid: %d\n", info.Proc.Pid)
				fmt.Printf("runnerInfo proc tid: %d\n", info.Proc.Tid)
				fmt.Printf("--------------------------------------------------\n")

				utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, pid int) *ExpectedFsnotifyEvent {
					return &ExpectedFsnotifyEvent{
						Type: "inotify",

						IMask: 134217736, // 134217736 = 0x08000008 = FS_CLOSE_WRITE | FS_EVENT_ON_CHILD
						Name:  filename,

						Timestamp: utils.NormalizedStr,

						TraceeMntnsId: utils.NormalizedInt,
						TracerMntnsId: utils.NormalizedInt,

						FaType:     utils.NormalizedStr,
						FaResponse: utils.NormalizedStr,

						IWd:     utils.NormalizedInt,
						IIno:    utils.NormalizedInt,
						IInoDir: utils.NormalizedInt,
					}
				})(t, info, 0, events)
			},
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var filename string
			runner := utilstest.NewRunnerWithTest(t, testCase.runnerConfig)

			normalizeEvent := func(event *ExpectedFsnotifyEvent) {
				utils.NormalizeString(&event.Timestamp)

				utils.NormalizeProc(&event.TraceeProc)
				utils.NormalizeProc(&event.TracerProc)
				utils.NormalizeInt(&event.TraceeMntnsId)
				utils.NormalizeInt(&event.TracerMntnsId)

				utils.NormalizeInt(&event.TraceeUId)
				utils.NormalizeInt(&event.TraceeGId)
				utils.NormalizeInt(&event.TracerUId)
				utils.NormalizeInt(&event.TracerGId)

				utils.NormalizeInt(&event.Prio)
				utils.NormalizeInt(&event.FaMask)

				utils.NormalizeString(&event.FaType)
				utils.NormalizeInt(&event.FaPId)
				utils.NormalizeInt(&event.FaFlags)
				utils.NormalizeInt(&event.FaFFlags)
				utils.NormalizeString(&event.FaResponse)

				utils.NormalizeInt(&event.IWd)
				utils.NormalizeInt(&event.ICookie)
				utils.NormalizeInt(&event.IIno)
				utils.NormalizeInt(&event.IInoDir)
			}
			onGadgetRun := func(gadgetCtx operators.GadgetContext) error {
				utilstest.RunWithRunner(t, runner, func() error {
					var err error
					filename, err = testCase.generateEvent()
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

			testCase.validateEvent(t, runner.Info, filename, gadgetRunner.CapturedEvents)
		})
	}
}

func generateEvent() (string, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return "", err
	}
	// defer watcher.Close()

	err = watcher.Add("/tmp/")
	if err != nil {
		return "", err
	}

	touchCmd := exec.Command("touch", "/tmp/ABCDE")
	err = touchCmd.Run()
	if err != nil {
		return "", err
	}

	return "ABCDE", nil
}
