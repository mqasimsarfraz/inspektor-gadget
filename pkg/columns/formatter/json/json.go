// Copyright 2022 The Inspektor Gadget authors
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

package json

import (
	"encoding/json"
	"reflect"
	"strconv"

	"github.com/kinvolk/inspektor-gadget/pkg/columns"
)

type column[T any] struct {
	name   string
	nameb  []byte
	column *columns.Column[T]
}

type JSONFormatter[T any] struct {
	options *Options
	columns []*column[T]
	scratch []byte
}

// NewFormatter returns a JSONFormatter that will turn entries of type T into JSON representation
func NewFormatter[T any](columns columns.ColumnMap[T], options ...Option) *JSONFormatter[T] {
	opts := DefaultOptions()
	for _, o := range options {
		o(opts)
	}

	cols := make([]*column[T], 0)
	for _, col := range columns.GetOrderedColumns() {
		name, _ := json.Marshal(col.Name)
		cols = append(cols, &column[T]{
			column: col,
			name:   string(name) + ": ",
			nameb:  []byte(string(name) + ": "),
		})
	}

	tf := &JSONFormatter[T]{
		options: opts,
		columns: cols,
		scratch: make([]byte, 1024),
	}
	return tf
}

// FormatEntry returns an entry as a formatted string, respecting the given formatting settings
func (f *JSONFormatter[T]) FormatEntry(entry *T) string {
	if entry == nil {
		return ""
	}

	entryValue := reflect.ValueOf(entry)

	buf := bufpool.Get().(*buffer)
	buf.b = buf.b[:0]
	defer bufpool.Put(buf)

	buf.b = append(buf.b, '{')
	for i, col := range f.columns {
		if i > 0 {
			buf.b = append(buf.b, []byte(", ")...)
		}
		buf.b = append(buf.b, col.nameb...)

		// Harvest low-hanging fruit
		switch col.column.Kind() {
		case reflect.Int,
			reflect.Int8,
			reflect.Int16,
			reflect.Int32,
			reflect.Int64:
			buf.b = strconv.AppendInt(buf.b, col.column.GetRef(entryValue).Int(), 10)
			continue
		case reflect.Uint,
			reflect.Uint8,
			reflect.Uint16,
			reflect.Uint32,
			reflect.Uint64:
			buf.b = strconv.AppendUint(buf.b, col.column.GetRef(entryValue).Uint(), 10)
			continue
		case reflect.Bool:
			if col.column.GetRef(entryValue).Bool() {
				buf.b = append(buf.b, []byte("true")...)
			} else {
				buf.b = append(buf.b, []byte("false")...)
			}
			continue
		}

		// let go stdlib handle all the more fancy stuff ;)
		val, _ := json.Marshal(col.column.GetRef(entryValue).Interface())
		buf.b = append(buf.b, val...)
	}
	buf.b = append(buf.b, '}')
	return string(buf.b)
}
