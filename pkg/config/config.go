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

package config

import (
	"github.com/inspektor-gadget/inspektor-gadget/pkg/config/defaults"
)

const (
	// Verbose is used to enable verbose output
	Verbose = "verbose"

	// AutoSDUnitRestart is used to enable the auto restart of systemd units
	AutoSDUnitRestart = "auto-sd-unit-restart"

	// AutoMountFilesystems is used to enable the auto mount of filesystems
	AutoMountFilesystems = "auto-mount-filesystems"

	// AutoWSLWorkaround is used to enable the auto workaround for WSL
	AutoWSLWorkaround = "auto-wsl-workaround"
)

type IGConfig struct {
	Verbose bool `mapstructure:"verbose"`

	AutoSDUnitRestart    bool `mapstructure:"auto-sd-unit-restart"`
	AutoMountFilesystems bool `mapstructure:"auto-mount-filesystems"`
	AutoWSLWorkaround    bool `mapstructure:"auto-wsl-workaround"`
}

// Config represents the IG configuration
var Config = &IGConfig{
	Verbose:              defaults.Verbose,
	AutoSDUnitRestart:    defaults.AutoSDUnitRestart,
	AutoMountFilesystems: defaults.AutoMountFilesystems,
	AutoWSLWorkaround:    defaults.AutoWSLWorkaround,
}
