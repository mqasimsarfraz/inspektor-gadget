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
	"testing"
)

func TestBucketConfig_String(t *testing.T) {
	tests := []struct {
		name string
		c    *BucketConfig
		want string
	}{
		{
			name: "empty",
			c:    &BucketConfig{},
			want: "-0-0-0.000000",
		},
		{
			name: "full",
			c: &BucketConfig{
				Type:       "test",
				Min:        1,
				Max:        2,
				Multiplier: 3,
			},
			want: "test-1-2-3.000000",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.String(); got != tt.want {
				t.Errorf("BucketConfig.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_bucketConfigFromString(t *testing.T) {
	tests := []struct {
		name    string
		cfg     string
		want    *BucketConfig
		wantErr bool
	}{
		{
			name:    "empty",
			cfg:     "",
			want:    &BucketConfig{},
			wantErr: true,
		},
		{
			name:    "invalid",
			cfg:     "invalid",
			want:    &BucketConfig{},
			wantErr: true,
		},
		{
			name:    "invalid bucket type",
			cfg:     "invalid-0-0-0",
			want:    &BucketConfig{},
			wantErr: true,
		},
		{
			name:    "invalid bucket min",
			cfg:     "exp2-invalid-0-0",
			want:    &BucketConfig{},
			wantErr: true,
		},
		{
			name:    "invalid bucket max",
			cfg:     "exp2-0-invalid-0",
			want:    &BucketConfig{},
			wantErr: true,
		},
		{
			name:    "invalid bucket multiplier",
			cfg:     "exp2-0-0-invalid",
			want:    &BucketConfig{},
			wantErr: true,
		},
		{
			name:    "valid",
			cfg:     "exp2-0-20-0.0001",
			want:    &BucketConfig{Type: "exp2", Min: 0, Max: 20, Multiplier: 0.0001},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := bucketConfigFromString(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("bucketConfigFromString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				if got.Type != tt.want.Type {
					t.Errorf("bucketConfigFromString() BucketType = %v, want %v", got.Type, tt.want.Type)
				}
				if got.Min != tt.want.Min {
					t.Errorf("bucketConfigFromString() BucketMin = %v, want %v", got.Min, tt.want.Min)
				}
				if got.Max != tt.want.Max {
					t.Errorf("bucketConfigFromString() BucketMax = %v, want %v", got.Max, tt.want.Max)
				}
				if got.Multiplier != tt.want.Multiplier {
					t.Errorf("bucketConfigFromString() BucketMultiplier = %v, want %v", got.Multiplier, tt.want.Multiplier)
				}
			}
		})

	}
}

func Test_exp2Buckets(t *testing.T) {
	cfg := &BucketConfig{Type: BucketTypeExp2, Min: 0, Max: 10, Multiplier: 0.0001}
	got := cfg.buckets()
	want := []float64{
		0.0001, 0.0002, 0.0004, 0.0008, 0.0016, 0.0032, 0.0064, 0.0128, 0.0256, 0.0512,
	}
	if len(got) != len(want) {
		t.Errorf("exp2Buckets() = %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("exp2Buckets() = %v, want %v", got, want)
		}
	}
}

func Test_linearBuckets(t *testing.T) {
	cfg := &BucketConfig{Type: BucketTypeLinear, Min: 0, Max: 10, Multiplier: 0.0001}
	got := cfg.buckets()
	want := []float64{
		0, 0.0001, 0.0002, 0.0003, 0.0004, 0.0005, 0.0006, 0.0007, 0.0008, 0.0009,
	}
	if len(got) != len(want) {
		t.Errorf("linearBuckets() = %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("linearBuckets() = %v, want %v", got, want)
		}
	}
}
