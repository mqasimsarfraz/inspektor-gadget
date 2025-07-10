package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"strings"
)

const (
	tcpListenAddr = "0.0.0.0:8080"
	tcpNumWorkers = 50
)

type tcpServer struct {
	listener net.Listener
}

func NewTCPServer(_ string) (Generator, error) {
	return &tcpServer{}, nil
}

func (s *tcpServer) Start() error {
	listener, err := net.Listen("tcp", tcpListenAddr)
	if err != nil {
		return fmt.Errorf("failed to bind to TCP %s: %w", tcpListenAddr, err)
	}

	s.listener = listener
	fmt.Printf("TCP server listening on %s with %d worker goroutines\n", tcpListenAddr, tcpNumWorkers)

	for range tcpNumWorkers {
		go s.acceptConnections()
	}
	return nil
}

func (s *tcpServer) Stop() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *tcpServer) acceptConnections() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		go handleTCPConnection(conn)
	}
}

func handleTCPConnection(conn net.Conn) {
	defer conn.Close()

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		message := strings.TrimSpace(scanner.Text())

		// Respond to ping with pong
		if message == "Ping" {
			_, err := conn.Write([]byte("Pong\n"))
			if err != nil {
				log.Printf("Write error: %v", err)
				return
			}
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Scanner error: %v", err)
	}
}

func init() {
	// Register the TCP server generator
	RegisterGenerator("tcp-server", NewTCPServer)
}
