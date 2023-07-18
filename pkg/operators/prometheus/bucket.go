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
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/shopspring/decimal"
	log "github.com/sirupsen/logrus"
)

const (
	prefix = "internal"
	sep    = "_"
	sepCfg = "-"
)

type BucketType string

const (
	BucketTypeExp2   BucketType = "exp2"
	BucketTypeLinear BucketType = "linear"
)

var allBucketTypes = map[BucketType]struct{}{
	BucketTypeExp2:   {},
	BucketTypeLinear: {},
}

type BucketConfig struct {
	Type       BucketType
	Min        int
	Max        int
	Multiplier float64
}

func bucketConfigFromString(cfg string) (*BucketConfig, error) {
	parts := strings.Split(cfg, sepCfg)
	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid view config: %s", cfg)
	}
	if _, ok := allBucketTypes[BucketType(parts[0])]; !ok {
		return nil, fmt.Errorf("invalid bucket type: %s", parts[0])
	}
	bmin, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid bucket min: %s", parts[1])
	}
	bmax, err := strconv.Atoi(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid bucket max: %s", parts[2])
	}
	bmul, err := strconv.ParseFloat(parts[3], 64)
	if err != nil {
		return nil, fmt.Errorf("invalid bucket multiplier: %s", parts[3])
	}
	return &BucketConfig{
		Type:       BucketType(parts[0]),
		Min:        bmin,
		Max:        bmax,
		Multiplier: bmul,
	}, nil
}

func (c *BucketConfig) String() string {
	return fmt.Sprintf("%s-%d-%d-%f", c.Type, c.Min, c.Max, c.Multiplier)
}

func (c *BucketConfig) HistogramName(name string) string {
	return prefix + sep + c.String() + sep + name
}

func (c *BucketConfig) buckets() []float64 {
	switch c.Type {
	case BucketTypeExp2:
		return exp2Buckets(c.Min, c.Max, c.Multiplier)
	case BucketTypeLinear:
		return linearBuckets(c.Min, c.Max, c.Multiplier)
	default:
		log.Warnf("unknown bucket type: %s", c.Type)
		return nil
	}
}

func exp2Buckets(min, max int, multiplier float64) []float64 {
	buckets := make([]float64, 0, max-min)
	for i := min; i < max; i++ {
		buckets = append(buckets, math.Pow(2, float64(i))*multiplier)
	}
	return buckets
}

func linearBuckets(min, max int, multiplier float64) []float64 {
	buckets := make([]float64, 0, max-min)
	for i := min; i < max; i++ {
		bucketId := decimal.NewFromInt(int64(i))
		bucketValue, _ := bucketId.Mul(decimal.NewFromFloat(multiplier)).Float64()
		buckets = append(buckets, bucketValue)
	}
	return buckets
}
