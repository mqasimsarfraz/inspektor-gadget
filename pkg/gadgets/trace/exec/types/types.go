// Copyright 2019-2024 The Inspektor Gadget authors
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

package types

import (
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type Event struct {
	eventtypes.Event
	eventtypes.WithMountNsID

	Pid           uint32   `json:"pid,omitempty" column:"pid,template:pid"`
	Tid           uint32   `json:"tid,omitempty" column:"tid,template:pid"`
	Ppid          uint32   `json:"ppid,omitempty" column:"ppid,template:pid"`
	Ptid          uint32   `json:"ptid,omitempty" column:"ptid,template:pid"`
	Comm          string   `json:"comm,omitempty" column:"comm,template:comm"`
	Pcomm         string   `json:"pcomm,omitempty" column:"pcomm,template:comm"`
	Retval        int      `json:"ret,omitempty" column:"ret,width:3,fixed"`
	Args          []string `json:"args,omitempty" column:"args,width:40"`
	Uid           uint32   `json:"uid" column:"uid,template:uid,hide"`
	Username      string   `json:"user,omitempty" column:"user,hide"`
	Gid           uint32   `json:"gid" column:"gid,template:gid,hide"`
	Groupname     string   `json:"group,omitempty" column:"group,hide"`
	UpperLayer    bool     `json:"upperlayer" column:"upperlayer,width:10,fixed,hide"`
	PupperLayer   bool     `json:"pupperlayer" column:"pupperlayer,width:11,fixed,hide"`
	LoginUid      uint32   `json:"loginuid" column:"loginuid,template:uid,hide"`
	SessionId     uint32   `json:"sessionid" column:"sessionid,minWidth:10,hide"`
	Cwd           string   `json:"cwd,omitempty" column:"cwd,width:40" columnTags:"param:paths"`
	ExePath       string   `json:"exepath,omitempty" column:"exepath,width:40" columnTags:"param:paths"`
	File          string   `json:"file,omitempty" column:"file,width:40" columnTags:"param:paths"`
	ParentExePath string   `json:"parent_exepath,omitempty" column:"parent_exepath,width:40" columnTags:"param:paths"`
}

func (e *Event) GetUid() uint32 {
	return e.Uid
}

func (e *Event) SetUserName(username string) {
	e.Username = username
}

func (e *Event) GetGid() uint32 {
	return e.Gid
}

func (e *Event) SetGroupName(groupname string) {
	e.Groupname = groupname
}

func GetColumns() *columns.Columns[Event] {
	execColumns := columns.MustCreateColumns[Event]()

	execColumns.MustSetExtractor("args", func(event *Event) any {
		return strings.Join(event.Args, " ")
	})

	return execColumns
}

func Base(ev eventtypes.Event) *Event {
	return &Event{
		Event: ev,
	}
}
