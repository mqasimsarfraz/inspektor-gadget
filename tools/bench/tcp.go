package main

import (
	"fmt"
	"net"
	"strings"
	"time"
)

type tcpClientGenerator struct {
	baseGenerator
}

type tcpClientConf struct {
	server string
	maxRPS int
}

func NewTCPClient(confStr string) (Generator, error) {
	conf, err := parseTCPConfStr(confStr)
	if err != nil {
		return nil, fmt.Errorf("parsing TCP client config: %w", err)
	}

	cb := func() error {
		conn, err := net.DialTimeout("tcp", conf.server, 5*time.Second)
		if err != nil {
			return err
		}
		defer conn.Close()

		// Send a simple message to the server
		_, err = conn.Write([]byte("Ping\n"))
		if err != nil {
			return err
		}

		// Optional: read response
		buffer := make([]byte, 1024)
		_, err = conn.Read(buffer)
		return err
	}

	g := &tcpClientGenerator{
		baseGenerator: NewBaseGen(cb),
	}

	return g, nil
}

func parseTCPConfStr(confStr string) (*tcpClientConf, error) {
	tcpConf := tcpClientConf{
		maxRPS: eventsPerSecond,
	}

	parts := strings.Split(confStr, ";")

	for _, part := range parts {
		confParts := strings.SplitN(part, "=", 2)
		confName := confParts[0]
		confVal := confParts[1]

		switch confName {
		case "server":
			tcpConf.server = confVal
		}
	}

	return &tcpConf, nil
}

func init() {
	RegisterGenerator("tcp", NewTCPClient)
}
