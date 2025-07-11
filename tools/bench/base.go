package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	ExecutionModeGoroutine = "goroutine"
	ExecutionModeProcess   = "process"
)

type baseGenerator struct {
	rateLimiter *RateLimiter
	done        chan struct{}
	fn          func() error
}

func NewBaseGen(cb func() error) baseGenerator {
	return baseGenerator{
		fn: cb,
	}
}

func (g *baseGenerator) Start() error {

	g.done = make(chan struct{})

	// TODO: Configurable
	g.rateLimiter = NewRateLimiter(eventsPerSecond)

	var counter uint64

	go func() {
		//fmt.Printf("Starting DNS request rate monitor...\n")
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()

		var lastCount uint64

		for {
			select {
			case <-ticker.C:
				currentCount := atomic.LoadUint64(&counter)
				rps := currentCount - lastCount
				fmt.Printf("events: %d total, %d req/s\n", currentCount, rps)

				lastCount = currentCount
			case <-g.done:
				return
			}
		}
	}()

	epsPerProcess := eventsPerSecond / numWorkers

	if executionMode == ExecutionModeProcess {
		fmt.Printf("Starting %d worker processes with %d events/sec each\n", numWorkers, epsPerProcess)
	}

	for i := range numWorkers {
		switch executionMode {
		case ExecutionModeGoroutine:
			go func() {
				for {
					g.rateLimiter.Run(func() {
						err := g.fn()
						if err == nil {
							atomic.AddUint64(&counter, 1)
						}
					})
				}
			}()
		case ExecutionModeProcess:
			go func(processID int) {
				fmt.Printf("Starting worker process %d (PID will be assigned)\n", processID)

				var eventArg string
				for idx, arg := range os.Args {
					if strings.HasPrefix(arg, "--events=") {
						eventArg = arg
					} else if arg == "--events" {
						if idx+1 > len(os.Args) {
							fmt.Printf("Process %d: Error: --events argument is missing a value.\n", processID)
							return
						}
						eventArg = arg + "=" + os.Args[idx+1]
					}
				}
				if eventArg == "" {
					fmt.Printf("Process %d: No event argument found in command line arguments.\n", processID)
					return
				}

				cmd := exec.Command(os.Args[0],
					eventArg,
					"--execution-mode", ExecutionModeGoroutine,
					"--num-workers", "1",
					"--events-per-second", strconv.Itoa(epsPerProcess),
				)
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr

				// Set environment variable to identify child process
				cmd.Env = append(os.Environ(), fmt.Sprintf("BENCH_PROCESS_ID=%d", processID))

				fmt.Printf("Process %d: Starting with command: %s\n", processID, strings.Join(cmd.Args, " "))

				err := cmd.Start()
				if err != nil {
					fmt.Printf("Process %d: Error starting child process: %v\n", processID, err)
					return
				}

				fmt.Printf("Process %d: Started with PID %d\n", processID, cmd.Process.Pid)

				err = cmd.Wait()
				if err != nil {
					fmt.Printf("Process %d (PID %d): Process exited with error: %v\n", processID, cmd.Process.Pid, err)
				} else {
					fmt.Printf("Process %d (PID %d): Process completed successfully\n", processID, cmd.Process.Pid)
				}
			}(i)
		}
	}
	return nil
}

func (g *baseGenerator) Stop() error {
	fmt.Printf("Stopping DNS client generator...\n")

	close(g.done)
	g.rateLimiter.Close()

	return nil
}
