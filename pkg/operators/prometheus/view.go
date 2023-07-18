// Copyright 2023 The Inspektor Gadget authors
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

package prometheus

import (
	"strings"

	log "github.com/sirupsen/logrus"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/aggregation"
)

// histogramView allows modifying aggregation for histogram instruments.
// It will extract view config from the instrument's name to determine bucket configuration.
// The instrument name must be of the form internal_<view-config>_<name>, where <view config> is
// a string of the form <bucket-type>-<bucket-min>-<bucket-max>-<bucket-multiplier>.
// The exporter will use <name> from internal_<view-config>_<name> as the final metric name.
func histogramView(instrument sdkmetric.Instrument) (sdkmetric.Stream, bool) {
	if instrument.Kind != sdkmetric.InstrumentKindHistogram {
		return sdkmetric.Stream{}, false
	}
	if !strings.HasPrefix(instrument.Name, prefix) {
		return sdkmetric.Stream{}, false
	}
	parts := strings.Split(instrument.Name, sep)
	if len(parts) < 3 {
		log.Warnf("invalid histogram name: %s", instrument.Name)
		return sdkmetric.Stream{}, false
	}
	cfg, err := bucketConfigFromString(parts[1])
	if err != nil {
		log.Warnf("error getting view config from histogram name: %s", err)
		return sdkmetric.Stream{}, false
	}
	return sdkmetric.Stream{
		Name:        strings.Join(parts[2:], sep),
		Description: instrument.Description,
		Unit:        instrument.Unit,
		Aggregation: aggregation.ExplicitBucketHistogram{
			Boundaries: cfg.buckets(),
		},
	}, true
}
