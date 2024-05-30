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
	"strings"

	"github.com/spf13/viper"
)

const (
	configKey  = "config"
	configType = "yaml"
	envPrefix  = "INSPEKTOR_GADGET"
)

var configPaths = []string{"/etc/ig/", "$HOME/.ig/", "."}

func NewViper() *viper.Viper {
	vp := viper.New()
	vp.SetConfigName(configKey)
	vp.SetConfigType(configType)
	vp.SetEnvPrefix(envPrefix)
	vp.AutomaticEnv()
	vp.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	for _, path := range configPaths {
		vp.AddConfigPath(path)
	}

	return vp
}
