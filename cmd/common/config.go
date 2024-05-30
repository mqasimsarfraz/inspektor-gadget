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
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/config"
)

func AddConfigHandler(cmd *cobra.Command) {
	cmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		return InitConfig(cmd)
	}
}

func InitConfig(cmd *cobra.Command) error {
	vp := config.NewViper()

	// don't check for errors, as the config file is optional
	vp.ReadInConfig()

	// bind flags and populate the config
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		if f.Name != "help" {
			err := vp.BindPFlag(f.Name, f)
			if err != nil {
				log.Warnf("Failed to bind flag %s: %v", f.Name, err)
			}
		}
	})

	err := vp.Unmarshal(config.Config)
	if err != nil {
		log.Warnf("Failed to unmarshal config: %v", err)
	}

	checkVerboseFlag()
	if vp.ConfigFileUsed() != "" {
		log.Debugf("Using config file: %s", vp.ConfigFileUsed())
	} else {
		log.Debugf("No config file used")
	}

	return nil
}
