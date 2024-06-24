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

package common

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/config"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

var configPath string

// AddConfigFlag adds the --config flag to the command
func AddConfigFlag(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(&configPath, "config", "", "", "config file to use")
}

// InitConfig initializes the config by reading the config file and setting root flags
func InitConfig(rootCmd *cobra.Command) error {
	// set the config file path if it is provided
	if configPath != "" {
		config.Config = config.NewWithPath(configPath)
	}

	// we do not want to fail if the config file is not found
	config.Config.ReadInConfig()

	return nil
}

// SetFlagsForParams sets the flags for the given params based on the config
func SetFlagsForParams(cmd *cobra.Command, params *params.Params, configPrefix string) error {
	for k := range params.ParamMap() {
		f := cmd.Flags().Lookup(k)
		if f == nil {
			continue
		}
		// Apply the config value to the flag when the flag is not set and config value is set
		if !f.Changed && config.Config.IsSet(configPrefix+k) {
			err := f.Value.Set(config.Config.GetString(configPrefix + k))
			if err != nil {
				return fmt.Errorf("setting flag %s: %w", k, err)
			}
		}
	}
	return nil
}
