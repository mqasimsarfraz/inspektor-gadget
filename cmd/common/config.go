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
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/config"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

var configPath string

// TODO: Perhaps this could be params so we can use the same mechanism for both
var rootFlags = map[string][]string{
	"gadgetctl":      {"verbose"},
	"ig":             {"verbose", "auto-sd-unit-restart", "auto-mount-filesystems", "auto-wsl-workaround"},
	"kubectl-gadget": {"verbose", "request-timeout", "client-certificate", "client-key", "insecure-skip-tls-verify", "kubeconfig", "server", "tls-server-name", "token"},
}

// AddConfigFlag adds the --config flag to the command
func AddConfigFlag(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(&configPath, "config", "", "", "config file to use")
}

// InitConfig initializes the config by reading the config file and setting root flags
func InitConfig(rootCmd *cobra.Command) error {
	if _, ok := rootFlags[rootCmd.Name()]; !ok {
		return fmt.Errorf("root flags not defined for %s", rootCmd.Name())
	}

	// set the config file path if it is provided
	if configPath != "" {
		config.Config = config.NewWithPath(configPath)
	}

	// we do not want to fail if the config file is not found
	config.Config.ReadInConfig()

	// set the root flags based on the config
	for _, fn := range rootFlags[rootCmd.Name()] {
		f := rootCmd.PersistentFlags().Lookup(fn)
		if f == nil {
			return fmt.Errorf("flag %s not found", fn)
		}

		// Bind the env variable to the flag
		config.Config.BindEnv(fn)

		// Apply the config value to the flag when the flag is not set and env/config value is set
		if !f.Changed && config.Config.IsSet(f.Name) {
			err := f.Value.Set(config.Config.GetString(f.Name))
			if err != nil {
				return fmt.Errorf("setting flag %s: %w", f.Name, err)
			}
		}
	}

	return nil
}

// SetFlagsForParams sets the flags for the given params based on the config
func SetFlagsForParams(cmd *cobra.Command, params *params.Params, configPrefix string) error {
	for k := range params.ParamMap() {
		f := cmd.Flags().Lookup(k)
		if f == nil {
			continue
		}

		// Apply the config value to the flag when the flag is not set and env/config value is set
		if !f.Changed {
			// we need to bind env without the prefix to avoid long names like INSPEKTOR_GADGET_OPERATOR_NAME_KEY
			config.Config.BindEnv(k)

			if config.Config.IsSet(k) {
				if err := f.Value.Set(config.Config.GetString(k)); err != nil {
					return fmt.Errorf("setting flag from env %s: %w", k, err)
				}
			} else if config.Config.IsSet(configPrefix + k) {
				if err := f.Value.Set(config.Config.GetString(configPrefix + k)); err != nil {
					return fmt.Errorf("setting flag from config %s: %w", configPrefix+k, err)
				}
			}
		}
	}
	return nil
}

func NewConfigCmd(runtime runtime.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Configuration commands",
	}
	defaultCmd := &cobra.Command{
		Use:   "default",
		Short: "Print the default configuration",
	}
	viewCmd := &cobra.Command{
		Use:   "view",
		Short: "Print the current configuration",
	}
	cmd.AddCommand(defaultCmd)
	cmd.AddCommand(viewCmd)
	AddConfigFlag(cmd)

	defaultCmd.Run = func(cmd *cobra.Command, args []string) {
		var defaultConfig struct {
			RuntimeConfig  map[string]string            `yaml:"runtime"`
			OperatorConfig map[string]map[string]string `yaml:"operator"`
			RootConfig     map[string]string            `yaml:",inline"`
		}

		runtimeConfig := make(map[string]string)
		runtime.GlobalParamDescs().ToParams().CopyToMap(runtimeConfig, "")
		defaultConfig.RuntimeConfig = runtimeConfig

		opConfig := make(map[string]map[string]string)
		for _, op := range operators.GetDataOperators() {
			opConfig[strings.ToLower(op.Name())] = make(map[string]string)
			apihelpers.ToParamDescs(op.GlobalParams()).ToParams().CopyToMap(opConfig[strings.ToLower(op.Name())], "")
		}

		opConfig["oci"] = make(map[string]string)
		apihelpers.ToParamDescs(ocihandler.OciHandler.InstanceParams()).ToParams().CopyToMap(opConfig["oci"], "")
		defaultConfig.OperatorConfig = opConfig

		defaultConfig.RootConfig = make(map[string]string)
		for _, fn := range rootFlags[cmd.Root().Name()] {
			f := cmd.Root().PersistentFlags().Lookup(fn)
			if f == nil {
				log.Fatalf("flag %s not found", fn)
			}
			defaultConfig.RootConfig[fn] = f.DefValue
		}

		out, err := yaml.Marshal(defaultConfig)
		if err != nil {
			log.Fatalf("failed to marshal config: %v", err)
		}

		fmt.Print(string(out))
	}

	viewCmd.Run = func(cmd *cobra.Command, args []string) {
		cp := config.Config.ConfigFileUsed()
		if configPath != "" {
			cp = configPath
		}
		cfg, err := os.ReadFile(cp)
		if err != nil {
			log.Fatalf("failed to read config: %v", err)
		}
		fmt.Print(string(cfg))
	}

	return utils.MarkExperimental(cmd)
}
