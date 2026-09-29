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

package gadgetrunner

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPublicKeyFromEnvironment(t *testing.T) {
	publicKey := "test public key"
	t.Setenv("IG_PUBLIC_KEY_BASE64", base64.StdEncoding.EncodeToString([]byte(publicKey)))

	runner := NewGadgetRunner[struct{}](t, GadgetRunnerOpts[struct{}]{
		Image:   "test",
		Timeout: time.Second,
	})

	assert.Equal(t, publicKey, runner.globalParamValues["operator.oci.public-keys"])
}
