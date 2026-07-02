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

// This module parses the raw RESP (REdis Serialization Protocol) bytes captured
// by program.bpf.c and turns them into user-friendly fields: the command and
// key of a request, and the type/summary (including errors) of a reply.
//
// RESP reference: https://redis.io/docs/latest/develop/reference/protocol-spec/
package main

import (
	"fmt"
	"strconv"
	"strings"

	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

const (
	typeCommand uint8 = 0
	typeReply   uint8 = 1

	// maxDataSize must match REDIS_MAX_DATA in program.bpf.c.
	maxDataSize = 256

	// maxFieldLen bounds the length of the derived string fields so a large
	// argument or reply cannot blow up a column.
	maxFieldLen = 256
)

var (
	dataF, dataLenF, typeRawF    api.Field
	typeF, commandF, keyF, argsF api.Field
	replyF, errorF               api.Field
	payload                      []byte
)

//go:wasmexport gadgetInit
func gadgetInit() int32 {
	ds, err := api.GetDataSource("redis")
	if err != nil {
		api.Warnf("failed to get datasource: %s", err)
		return 1
	}

	if dataF, err = ds.GetField("data"); err != nil {
		api.Warnf("failed to get field data: %s", err)
		return 1
	}
	if dataLenF, err = ds.GetField("data_len"); err != nil {
		api.Warnf("failed to get field data_len: %s", err)
		return 1
	}
	if typeRawF, err = ds.GetField("type_raw"); err != nil {
		api.Warnf("failed to get field type_raw: %s", err)
		return 1
	}

	for _, f := range []struct {
		dst  *api.Field
		name string
		kind api.FieldKind
	}{
		{&typeF, "type", api.Kind_String},
		{&commandF, "command", api.Kind_String},
		{&keyF, "key", api.Kind_String},
		{&argsF, "args", api.Kind_String},
		{&replyF, "reply", api.Kind_String},
		{&errorF, "error", api.Kind_Bool},
	} {
		field, err := ds.AddField(f.name, f.kind)
		if err != nil {
			api.Warnf("failed to add field %s: %s", f.name, err)
			return 1
		}
		*f.dst = field
	}

	payload = make([]byte, maxDataSize)

	ds.Subscribe(func(source api.DataSource, data api.Data) {
		typeRaw, err := typeRawF.Uint8(data)
		if err != nil {
			api.Warnf("failed to get type_raw: %s", err)
			return
		}

		dataLen, err := dataLenF.Uint32(data)
		if err != nil {
			api.Warnf("failed to get data_len: %s", err)
			return
		}

		n, err := dataF.Bytes(data, payload)
		if err != nil {
			api.Warnf("failed to get data: %s", err)
			return
		}
		// Only the first min(dataLen, maxDataSize) bytes are meaningful.
		if uint32(n) > dataLen {
			n = uint32(dataLen)
		}
		buf := payload[:n]

		switch typeRaw {
		case typeCommand:
			typeF.SetString(data, "command")
			cmd, key, args := parseCommand(buf)
			commandF.SetString(data, cmd)
			keyF.SetString(data, key)
			argsF.SetString(data, args)
		case typeReply:
			typeF.SetString(data, "reply")
			isErr, summary := parseReply(buf)
			errorF.SetBool(data, isErr)
			replyF.SetString(data, summary)
		}
	}, 0)

	return 0
}

// parseCommand parses a client request and returns the command verb (upper
// cased), the first argument (usually the key), and the remaining arguments
// joined by spaces. Redis clients send commands either as a RESP array of bulk
// strings or, more rarely, as an inline space-separated command.
func parseCommand(b []byte) (command, key, args string) {
	var parts []string
	if len(b) > 0 && b[0] == '*' {
		parts = parseRESPArray(b)
	} else {
		// Inline command: everything up to the first CRLF, split on spaces.
		line, _, _ := readLine(b, 0)
		parts = strings.Fields(string(line))
	}

	if len(parts) == 0 {
		return "", "", ""
	}
	command = strings.ToUpper(parts[0])
	if len(parts) > 1 {
		key = parts[1]
		args = truncate(strings.Join(parts[1:], " "))
	}
	return command, truncate(key), args
}

// parseRESPArray parses "*<n>\r\n$<len>\r\n<data>\r\n..." into its elements. It
// is tolerant of truncation (the eBPF side only captures the first bytes): it
// returns whatever complete bulk strings it could read.
func parseRESPArray(b []byte) []string {
	countLine, pos, ok := readLine(b, 1) // skip '*'
	if !ok {
		return nil
	}
	count, err := strconv.Atoi(string(countLine))
	if err != nil || count < 0 {
		return nil
	}

	parts := make([]string, 0, count)
	for i := 0; i < count; i++ {
		if pos >= len(b) || b[pos] != '$' {
			break
		}
		lenLine, next, ok := readLine(b, pos+1)
		if !ok {
			break
		}
		strLen, err := strconv.Atoi(string(lenLine))
		if err != nil || strLen < 0 {
			break
		}
		if next+strLen > len(b) {
			// Truncated payload: keep as much as we have and stop.
			parts = append(parts, string(b[next:]))
			break
		}
		parts = append(parts, string(b[next:next+strLen]))
		pos = next + strLen + 2 // skip trailing CRLF
	}
	return parts
}

// parseReply summarizes a server reply and reports whether it is an error. It
// handles both RESP2 and RESP3 leading type bytes.
func parseReply(b []byte) (isErr bool, summary string) {
	if len(b) == 0 {
		return false, ""
	}

	line, _, _ := readLine(b, 1) // content after the type byte, up to CRLF
	rest := string(line)

	switch b[0] {
	case '+': // simple string, e.g. +OK
		return false, truncate(rest)
	case '-': // error, e.g. -WRONGTYPE Operation against a key...
		return true, truncate(rest)
	case ':': // integer
		return false, truncate(rest)
	case '(': // RESP3 big number
		return false, truncate(rest)
	case ',': // RESP3 double
		return false, truncate(rest)
	case '#': // RESP3 boolean, #t / #f
		if rest == "t" {
			return false, "true"
		}
		return false, "false"
	case '_': // RESP3 null
		return false, "(nil)"
	case '$', '=': // bulk / verbatim string
		n, err := strconv.Atoi(rest)
		if err != nil {
			return false, ""
		}
		if n < 0 {
			return false, "(nil)"
		}
		return false, fmt.Sprintf("(bulk: %d bytes)", n)
	case '!': // RESP3 bulk error
		n, err := strconv.Atoi(rest)
		if err != nil || n < 0 {
			return true, ""
		}
		// The error message follows on the next line.
		_, next, _ := readLine(b, 1)
		end := next + n
		if end > len(b) {
			end = len(b)
		}
		return true, truncate(string(b[next:end]))
	case '*': // array
		return replyAggregate("array", rest)
	case '~': // RESP3 set
		return replyAggregate("set", rest)
	case '>': // RESP3 push
		return replyAggregate("push", rest)
	case '%': // RESP3 map
		return replyAggregate("map", rest)
	default:
		return false, ""
	}
}

func replyAggregate(kind, countStr string) (bool, string) {
	n, err := strconv.Atoi(countStr)
	if err != nil {
		return false, "(" + kind + ")"
	}
	if n < 0 {
		return false, "(nil)"
	}
	return false, fmt.Sprintf("(%s: %d elements)", kind, n)
}

// readLine returns the bytes from start up to the next CRLF, the index just
// past that CRLF, and whether a CRLF was found. If no CRLF is present (e.g. the
// payload was truncated) it returns the remaining bytes and ok=false.
func readLine(b []byte, start int) (line []byte, next int, ok bool) {
	if start > len(b) {
		return nil, len(b), false
	}
	for i := start; i+1 < len(b); i++ {
		if b[i] == '\r' && b[i+1] == '\n' {
			return b[start:i], i + 2, true
		}
	}
	return b[start:], len(b), false
}

func truncate(s string) string {
	if len(s) > maxFieldLen {
		return s[:maxFieldLen]
	}
	return s
}

func main() {}
