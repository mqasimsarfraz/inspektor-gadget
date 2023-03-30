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

package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	pb "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgettracermanager/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // TODO
	},
}

type WebServer struct {
	runtime runtime.Runtime
}

func NewWebServer(runtime runtime.Runtime) *WebServer {
	return &WebServer{
		runtime: runtime,
	}
}

type GadgetStartRequest struct {
	ID             string            `json:"id"`
	GadgetName     string            `json:"gadgetName"`
	GadgetCategory string            `json:"gadgetCategory"`
	Params         map[string]string `json:"params"`
	Timeout        int               `json:"timeout"`
	LogLevel       int               `json:"logLevel"`
}

type GadgetStopRequest struct {
	ID string `json:"id"`
}

type GadgetEvent struct {
	ID      string          `json:"id"`
	Type    uint32          `json:"type,omitempty"`
	Payload json.RawMessage `json:"payload"`
}

type Command struct {
	Action  string          `json:"action"`
	Payload json.RawMessage `json:"payload"`
}

type wsConn struct {
	runtime    runtime.Runtime
	conn       *websocket.Conn
	gadgets    map[string]*gadgetcontext.GadgetContext
	gadgetLock sync.Mutex
}

func (c *wsConn) stopGadget(id string) error {
	c.gadgetLock.Lock()
	defer c.gadgetLock.Unlock()

	if gadget, ok := c.gadgets[id]; ok {
		gadget.Cancel()
	}
	return nil
}

func (c *wsConn) startGadget(ctx context.Context, request *GadgetStartRequest) error {
	c.gadgetLock.Lock()
	defer c.gadgetLock.Unlock()

	if _, ok := c.gadgets[request.ID]; ok {
		return fmt.Errorf("gadget with ID %q already exists", request.ID)
	}

	logger := logger.NewFromGenericLogger(&Logger{
		send: func(event *GadgetEvent) error {
			event.ID = request.ID
			err := c.conn.WriteJSON(event)
			if err != nil {
				// TODO: Shutdown
			}
			return nil
		},
		level: logger.Level(request.LogLevel),
		// fallbackLogger: s.logger, // TODO
	})

	// Build a gadget context and wire everything up
	gadgetDesc := gadgetregistry.Get(request.GadgetCategory, request.GadgetName)
	if gadgetDesc == nil {
		return fmt.Errorf("gadget not found: %s/%s", request.GadgetCategory, request.GadgetName)
	}

	// Get per gadget operators
	ops := operators.GetOperatorsForGadget(gadgetDesc)
	ops.Init(operators.GlobalParamsCollection())

	operatorParams := ops.ParamCollection()
	err := operatorParams.CopyFromMap(request.Params, "operator.")
	if err != nil {
		return fmt.Errorf("setting operator parameters: %w", err)
	}

	parser := gadgetDesc.Parser()

	runtimeParams := c.runtime.ParamDescs().ToParams()
	err = runtimeParams.CopyFromMap(request.Params, "runtime.")
	if err != nil {
		return fmt.Errorf("setting runtime parameters: %w", err)
	}

	gadgetParamDescs := gadgetDesc.ParamDescs()
	gadgetParamDescs.Add(gadgets.GadgetParams(gadgetDesc, parser)...)
	gadgetParams := gadgetParamDescs.ToParams()
	err = gadgetParams.CopyFromMap(request.Params, "")
	if err != nil {
		return fmt.Errorf("setting gadget parameters: %w", err)
	}

	if parser != nil {
		parser.SetLogCallback(logger.Logf)
		parser.SetEventCallback(func(ev any) {
			// Marshal JSON messages and wrap
			data, _ := json.Marshal(ev)
			event := &GadgetEvent{
				ID:      request.ID,
				Type:    pb.EventTypeGadgetPayload,
				Payload: data,
			}
			c.conn.WriteJSON(event)
		})
	}

	// Assign a unique ID - this will be used in the future
	runID := uuid.New().String()

	// Create new Gadget Context
	gadgetCtx := gadgetcontext.New(
		ctx,
		runID,
		c.runtime,
		runtimeParams,
		gadgetDesc,
		gadgetParams,
		operatorParams,
		parser,
		logger,
		time.Duration(request.Timeout),
	)

	c.gadgets[request.ID] = gadgetCtx

	go func() {
		defer gadgetCtx.Cancel()
		defer func() {
			c.gadgetLock.Lock()
			defer c.gadgetLock.Unlock()

			delete(c.gadgets, request.ID)
		}()

		// Hand over to runtime
		results, err := c.runtime.RunGadget(gadgetCtx)
		if err != nil {
			// return fmt.Errorf("running gadget: %w", err)
		}

		// Send result, if any
		for _, result := range results {
			// TODO: when used with fan-out, we need to add the node in here
			event := &GadgetEvent{
				ID:      request.ID,
				Type:    pb.EventTypeGadgetResult,
				Payload: result.Payload,
			}
			c.conn.WriteJSON(event)
		}
	}()

	return nil
}

func (c *wsConn) handle() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	defer func() {
		c.gadgetLock.Lock()
		defer c.gadgetLock.Unlock()

		for _, g := range c.gadgets {
			g.Cancel()
		}
	}()
	for {
		command := &Command{}
		err := c.conn.ReadJSON(&command)
		if err != nil {
			log.Debugf("error from ws: %v", err)
			return
		}
		switch command.Action {
		case "start":
			// Create a new gadget
			gadgetStartRequest := &GadgetStartRequest{}
			if err := json.Unmarshal(command.Payload, &gadgetStartRequest); err != nil {
				// TODO: report error
				continue
			}
			err := c.startGadget(ctx, gadgetStartRequest)
			if err != nil {
				log.Debugf("error from gadget: %v", err)
			}
		case "stop":
			gadgetStopRequest := &GadgetStopRequest{}
			if err := json.Unmarshal(command.Payload, &gadgetStopRequest); err != nil {
				// TODO: report error
				continue
			}
			err := c.stopGadget(gadgetStopRequest.ID)
			if err != nil {
				log.Debugf("error from gadget: %v", err)
			}

		}
	}
}

func (s *WebServer) serveWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("error upgrading: %v", err)
		return
	}
	defer conn.Close()
	(&wsConn{
		conn:    conn,
		runtime: s.runtime,
		gadgets: map[string]*gadgetcontext.GadgetContext{},
	}).handle()
}

func (s *WebServer) serveCatalog(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	catalog, _ := s.runtime.GetCatalog()
	json.NewEncoder(w).Encode(catalog)
}

func (s *WebServer) Run() error {
	http.HandleFunc("/catalog", func(w http.ResponseWriter, r *http.Request) {
		s.serveCatalog(w, r)
	})
	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("new ws")
		s.serveWebSocket(w, r)
	})
	return http.ListenAndServe(":8099", nil)
}

func NewWebCommand(runtime runtime.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "web",
		Short: "serve web-frontend",
		RunE: func(cmd *cobra.Command, args []string) error {
			ws := NewWebServer(runtime)
			return ws.Run()
		},
	}
}
