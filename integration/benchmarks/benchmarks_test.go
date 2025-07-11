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

package benchmarks

import (
	"encoding/csv"
	"flag"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	igtesting "github.com/inspektor-gadget/inspektor-gadget/pkg/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/containers"
	igrunner "github.com/inspektor-gadget/inspektor-gadget/pkg/testing/ig"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

var benchmark = flag.Bool("benchmark", false, "run benchmark tests")

type BenchmarkConfig struct {
	Ntimes            int                   `yaml:"ntimes"`
	OutputFolder      string                `yaml:"output_folder"`
	IgPath            string                `yaml:"ig_path"`
	IgFlags           []string              `yaml:"ig_flags"`
	IgRuntime         string                `yaml:"ig_runtime"`
	GadgetTag         string                `yaml:"gadget_tag"`
	GadgetRunDuration int                   `yaml:"gadget_run_duration"`
	WarmUpDuration    int                   `yaml:"warm_up_duration"`
	Tests             map[string]TestConfig `yaml:"tests"`
}

type TestConfig struct {
	GadgetName      string          `yaml:"gadgetName"`
	Server          *ServerConfig   `yaml:"server,omitempty"`
	Generator       GeneratorConfig `yaml:"generator"`
	EventsPerSecond []int           `yaml:"eventsPerSecond"`
	GadgetParams    []string        `yaml:"gadgetParams,omitempty"`
}

type ServerConfig struct {
	Image string `yaml:"image"`
	Cmd   string `yaml:"cmd"`
}

type GeneratorConfig struct {
	Image string `yaml:"image"`
	Cmd   string `yaml:"cmd"`
}

func TestMain(m *testing.M) {
	flag.Parse()

	if !*benchmark {
		fmt.Println("Skipping benchmark tests")
		os.Exit(0)
	}

	fmt.Println("Running benchmark tests")
	os.Exit(m.Run())
}

func TestBenchmarks(t *testing.T) {
	configData, err := os.ReadFile("benchmarks.yaml")
	require.NoError(t, err, "failed to read benchmarks.yaml")

	var config BenchmarkConfig
	err = yaml.Unmarshal(configData, &config)
	require.NoError(t, err, "failed to parse benchmarks.yaml")

	// set up the environment for benchmarks
	t.Setenv("IG_PATH", config.IgPath)
	t.Setenv("IG_FLAGS", strings.Join(config.IgFlags, " "))
	t.Setenv("IG_RUNTIME", config.IgRuntime)
	t.Setenv("GADGET_TAG", config.GadgetTag)

	// create the output folder if it doesn't exist
	if config.OutputFolder != "" {
		err := os.MkdirAll(config.OutputFolder, 0755)
		require.NoError(t, err, "failed to create output folder")
	}

	for gadgetName, testConfig := range config.Tests {
		t.Run(gadgetName, func(t *testing.T) {
			filePath := fmt.Sprintf("test_results_%s.csv", gadgetName)
			if config.OutputFolder != "" {
				filePath = fmt.Sprintf("%s/%s", config.OutputFolder, filePath)
			}

			file, err := os.Create(filePath)
			require.NoError(t, err)
			defer file.Close()

			writer := csv.NewWriter(file)
			defer writer.Flush()
			writer.Write([]string{"Name", "rps", "%cpu", "mem(MB)", "cpu_ci", "mem_ci", "runs", "lost"})

			for _, eventsPerSecond := range testConfig.EventsPerSecond {
				// TODO: another t.run for each RPS value?

				for _, useTracer := range []bool{false, true} {
					tName := "baseline"
					if useTracer {
						tName = "ig"
					}

					t.Logf("Starting test series for %s at %d RPS (%d runs)", tName, eventsPerSecond, config.Ntimes)

					result := testGadgetMultiple(t, &config, &testConfig, eventsPerSecond, useTracer, config.Ntimes)

					writer.Write([]string{
						tName,
						fmt.Sprintf("%v", eventsPerSecond),
						strconv.FormatFloat(result.cpuMean, 'f', 2, 64),
						strconv.FormatFloat(result.memMean, 'f', 2, 64),
						strconv.FormatFloat(result.cpuCI, 'f', 2, 64),
						strconv.FormatFloat(result.memCI, 'f', 2, 64),
						strconv.Itoa(config.Ntimes),
						strconv.FormatFloat(result.lostMean, 'f', 2, 64),
					})

					// Flush after each test to ensure data is written
					writer.Flush()
				}
			}
		})
	}
}

type linesCounter struct {
	lines uint64
}

func (c *linesCounter) Write(p []byte) (n int, err error) {
	// Count the number of lines in the input
	for _, b := range p {
		if b == '\n' {
			c.lines++
		}
	}
	return len(p), nil
}

type stat struct {
	cpu  float64
	mem  float64
	lost uint64
}

type statResult struct {
	cpuMean  float64
	cpuCI    float64
	memMean  float64
	memCI    float64
	lostMean float64
}

func testGadgetSingle(t *testing.T, bc *BenchmarkConfig, tc *TestConfig, conf any, usetracer bool) stat {
	tName := fmt.Sprintf("test-%s", tc.GadgetName)

	runDuration := bc.GadgetRunDuration
	timeoutParam := fmt.Sprintf("--timeout=%d", runDuration)
	sleepTimeout := time.Duration(runDuration) * time.Second
	warmUpTimeout := time.Duration(bc.WarmUpDuration) * time.Second
	// TODO: is it fine?
	cpuAndMemoryInitialDelay := time.Duration(runDuration/4) * time.Second

	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	containerFactory, err := containers.NewContainerFactory(utils.Runtime)
	require.NoError(t, err, "new container factory")
	serverContainerName := fmt.Sprintf("%s-server", tName)
	clientContainerName := fmt.Sprintf("%s-client", tName)

	var nsTest string
	//serverContainerOpts := []containers.ContainerOption{containers.WithContainerImage(tc.ServerImage)}
	clientContainerOpts := []containers.ContainerOption{containers.WithContainerImage(tc.Generator.Image)}

	// TODO: kubectl support is future work
	//	if utils.CurrentTestComponent == utils.KubectlGadgetTestComponent {
	//		nsTest = utils.GenerateTestNamespaceName(t, tName)
	//		testutils.CreateK8sNamespace(t, nsTest)
	//
	//		clientContainerOpts = append(clientContainerOpts, containers.WithContainerNamespace(nsTest))
	//		clientContainerOpts = append(clientContainerOpts, containers.WithUseExistingNamespace())
	//		serverContainerOpts = append(serverContainerOpts, containers.WithContainerNamespace(nsTest))
	//		serverContainerOpts = append(serverContainerOpts, containers.WithUseExistingNamespace())
	//	}

	var serverIP string

	if tc.Server != nil {
		serverContainerOpts := []containers.ContainerOption{containers.WithContainerImage(tc.Server.Image)}
		serverContainer := containerFactory.NewContainer(serverContainerName, tc.Server.Cmd, serverContainerOpts...)
		serverContainer.Start(t)
		t.Cleanup(func() {
			serverContainer.Stop(t)
		})

		serverIP = serverContainer.IP()
	}

	clientCmd := tc.Generator.Cmd
	// Replace placeholders with actual values
	clientCmd = strings.ReplaceAll(clientCmd, "{serverIP}", serverIP)
	clientCmd = strings.ReplaceAll(clientCmd, "{eventsPerSecond}", fmt.Sprintf("%d", conf))

	clientContainer := containerFactory.NewContainer(
		clientContainerName,
		clientCmd,
		clientContainerOpts...,
	)
	clientContainer.Start(t)
	t.Cleanup(func() {
		clientContainer.Stop(t)
	})

	var runnerOpts []igrunner.Option
	var testingOpts []igtesting.Option

	switch utils.CurrentTestComponent {
	case utils.IgLocalTestComponent:
		runnerOpts = append(runnerOpts, igrunner.WithFlags(fmt.Sprintf("-r=%s", utils.Runtime), timeoutParam))
	case utils.KubectlGadgetTestComponent:
		runnerOpts = append(runnerOpts, igrunner.WithFlags(fmt.Sprintf("-n=%s", nsTest), timeoutParam))
		testingOpts = append(testingOpts, igtesting.WithCbBeforeCleanup(utils.PrintLogsFn(nsTest)))
	}

	runnerOpts = append(runnerOpts, igrunner.WithFlags(tc.GadgetParams...))

	lost := uint64(0)

	var gadgetCmd igtesting.TestStep
	var lWriter *linesCounter
	if usetracer {
		// Count dropped events.
		runnerOpts = append(runnerOpts, igrunner.WithValidateStderrOutput(func(t *testing.T, output string) {
			// Parse output to count lost samples
			lines := strings.Split(output, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.Contains(line, "lost") && strings.Contains(line, "samples") {
					// Extract number from "lost <number> samples"
					parts := strings.Fields(line)
					for i, part := range parts {
						if part == "lost" && i+1 < len(parts) {
							if num, err := strconv.ParseUint(parts[i+1], 10, 64); err == nil {
								lost += num
							}
							break
						}
					}
				}
			}
		}))

		// check that the gadget captured data
		lWriter = &linesCounter{}
		runnerOpts = append(runnerOpts, igrunner.WithStdWriter(lWriter))
		gadgetCmd = igrunner.New(tc.GadgetName, runnerOpts...)
	} else {
		gadgetCmd = utils.Sleep(sleepTimeout)
	}

	initialDelay := cpuAndMemoryInitialDelay // Start capturing CPU and memory after an initial delay to avoid initial spikes
	if !usetracer {
		// If not using tracer, we can start capturing immediately
		initialDelay = 0
	}
	cpu := utils.Cpu(initialDelay)
	mem := utils.Memory(initialDelay)

	steps := []igtesting.TestStep{
		// warm up
		utils.Sleep(warmUpTimeout),

		cpu,
		mem,

		gadgetCmd,
	}

	igtesting.RunTestSteps(steps, t, testingOpts...)

	// TODO: how to associate to the number of generated events?
	if lWriter != nil {
		require.Greater(t, lWriter.lines, uint64(0), "Gadget %s should have captured some data", tc.GadgetName)
	}

	return stat{
		cpu:  cpu.Avg(),
		mem:  mem.Avg(),
		lost: lost / uint64(runDuration), // Convert lost events to per second
	}
}

func testGadgetMultiple(t *testing.T, bc *BenchmarkConfig, tc *TestConfig, comb any, usetracer bool, nRuns int) statResult {
	cpuValues := make([]float64, 0, nRuns)
	memValues := make([]float64, 0, nRuns)
	lostValues := make([]uint64, 0, nRuns)

	for i := 0; i < nRuns; i++ {
		t.Run(fmt.Sprintf("comb=%v_usetracer=%t_run=%d", comb, usetracer, i+1), func(t *testing.T) {
			t.Logf("Running test %d/%d for comb=%d, usetracer=%t", i+1, nRuns, comb, usetracer)
			result := testGadgetSingle(t, bc, tc, comb, usetracer)
			cpuValues = append(cpuValues, result.cpu)
			memValues = append(memValues, result.mem)
			lostValues = append(lostValues, result.lost)
		})
	}

	cpuMean, cpuCI := CalculateStats(cpuValues)
	fmt.Printf("CPU Mean: %.2f, CPU CI: %.2f\n", cpuMean, cpuCI)

	memMean, memCI := CalculateStats(memValues)
	fmt.Printf("Memory Mean: %.2f, Memory CI: %.2f\n", memMean, memCI)

	lostMean, _ := CalculateStats(lostValues)
	fmt.Printf("Lost Mean: %.2f\n", lostMean)

	return statResult{
		cpuMean:  cpuMean,
		cpuCI:    cpuCI,
		memMean:  memMean,
		memCI:    memCI,
		lostMean: lostMean,
	}
}

// Numeric is a constraint for numeric types
type Numeric interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 |
		~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 |
		~float32 | ~float64
}

// calculateStats calculates mean and 95% confidence interval for a slice of values
func CalculateStats[T Numeric](values []T) (mean, ci float64) {
	if len(values) == 0 {
		return 0, 0
	}

	// Calculate mean
	sum := 0.0
	for _, v := range values {
		sum += float64(v)
	}
	mean = sum / float64(len(values))

	if len(values) == 1 {
		// If only one value, confidence interval is not defined
		return mean, 0
	}

	// Calculate standard deviation
	sumSquares := 0.0
	for _, v := range values {
		diff := float64(v) - mean
		sumSquares += diff * diff
	}
	variance := sumSquares / float64(len(values)-1)
	stddev := math.Sqrt(variance)

	// Calculate 95% confidence interval (assuming t-distribution)
	// For small samples, we use t-value. For simplicity, using 2.0 as approximation
	// For more precision, would need to import a stats library
	tValue := 2.0
	if len(values) >= 30 {
		tValue = 1.96 // z-value for large samples
	}

	standardError := stddev / math.Sqrt(float64(len(values)))
	ci = tValue * standardError

	return mean, ci
}
