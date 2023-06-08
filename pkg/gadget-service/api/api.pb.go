// Copyright 2019-2021 The Inspektor Gadget authors
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

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.0
// 	protoc        v3.17.3
// source: api/api.proto

package api

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type GadgetRunRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// name of the gadget as returned by gadgetDesc.Name()
	GadgetName string `protobuf:"bytes,1,opt,name=gadgetName,proto3" json:"gadgetName,omitempty"`
	// category of the gadget as returned by gadgetDesc.Category()
	GadgetCategory string `protobuf:"bytes,2,opt,name=gadgetCategory,proto3" json:"gadgetCategory,omitempty"`
	// params is a combined map of all params a gadget could need (including those
	// of runtime and operators, which need specific prefixes, see implementation in
	// pkg/runtime/grpc)
	Params map[string]string `protobuf:"bytes,3,rep,name=params,proto3" json:"params,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	// a list of nodes the gadget should run on; if not specified, it should run
	// on all nodes
	Nodes []string `protobuf:"bytes,10,rep,name=nodes,proto3" json:"nodes,omitempty"`
	// if set to true, the gadget service should forward the request to each node
	// from the nodes list (or each node it knows, if the list is empty) and combine
	// their output
	FanOut bool `protobuf:"varint,11,opt,name=fanOut,proto3" json:"fanOut,omitempty"`
	// sets the requested log level (see pkg/logger/logger.go)
	LogLevel uint32 `protobuf:"varint,12,opt,name=logLevel,proto3" json:"logLevel,omitempty"`
	// time that a gadget should run; use 0, if the gadget should run until it's being
	// stopped or done
	Timeout int64 `protobuf:"varint,13,opt,name=timeout,proto3" json:"timeout,omitempty"`
}

func (x *GadgetRunRequest) Reset() {
	*x = GadgetRunRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_api_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GadgetRunRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GadgetRunRequest) ProtoMessage() {}

func (x *GadgetRunRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_api_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GadgetRunRequest.ProtoReflect.Descriptor instead.
func (*GadgetRunRequest) Descriptor() ([]byte, []int) {
	return file_api_api_proto_rawDescGZIP(), []int{0}
}

func (x *GadgetRunRequest) GetGadgetName() string {
	if x != nil {
		return x.GadgetName
	}
	return ""
}

func (x *GadgetRunRequest) GetGadgetCategory() string {
	if x != nil {
		return x.GadgetCategory
	}
	return ""
}

func (x *GadgetRunRequest) GetParams() map[string]string {
	if x != nil {
		return x.Params
	}
	return nil
}

func (x *GadgetRunRequest) GetNodes() []string {
	if x != nil {
		return x.Nodes
	}
	return nil
}

func (x *GadgetRunRequest) GetFanOut() bool {
	if x != nil {
		return x.FanOut
	}
	return false
}

func (x *GadgetRunRequest) GetLogLevel() uint32 {
	if x != nil {
		return x.LogLevel
	}
	return 0
}

func (x *GadgetRunRequest) GetTimeout() int64 {
	if x != nil {
		return x.Timeout
	}
	return 0
}

type GadgetStopRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *GadgetStopRequest) Reset() {
	*x = GadgetStopRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_api_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GadgetStopRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GadgetStopRequest) ProtoMessage() {}

func (x *GadgetStopRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_api_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GadgetStopRequest.ProtoReflect.Descriptor instead.
func (*GadgetStopRequest) Descriptor() ([]byte, []int) {
	return file_api_api_proto_rawDescGZIP(), []int{1}
}

// GadgetAttachRequest is used to attach to a running (persistent gadget) and get its results / events
type GadgetAttachRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
}

func (x *GadgetAttachRequest) Reset() {
	*x = GadgetAttachRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_api_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GadgetAttachRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GadgetAttachRequest) ProtoMessage() {}

func (x *GadgetAttachRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_api_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GadgetAttachRequest.ProtoReflect.Descriptor instead.
func (*GadgetAttachRequest) Descriptor() ([]byte, []int) {
	return file_api_api_proto_rawDescGZIP(), []int{2}
}

func (x *GadgetAttachRequest) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

type GadgetEvent struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types are specified in consts.go. Upper 16 bits are used for log severity levels
	Type    uint32 `protobuf:"varint,1,opt,name=type,proto3" json:"type,omitempty"`
	Seq     uint32 `protobuf:"varint,2,opt,name=seq,proto3" json:"seq,omitempty"`
	Payload []byte `protobuf:"bytes,3,opt,name=payload,proto3" json:"payload,omitempty"`
}

func (x *GadgetEvent) Reset() {
	*x = GadgetEvent{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_api_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GadgetEvent) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GadgetEvent) ProtoMessage() {}

func (x *GadgetEvent) ProtoReflect() protoreflect.Message {
	mi := &file_api_api_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GadgetEvent.ProtoReflect.Descriptor instead.
func (*GadgetEvent) Descriptor() ([]byte, []int) {
	return file_api_api_proto_rawDescGZIP(), []int{3}
}

func (x *GadgetEvent) GetType() uint32 {
	if x != nil {
		return x.Type
	}
	return 0
}

func (x *GadgetEvent) GetSeq() uint32 {
	if x != nil {
		return x.Seq
	}
	return 0
}

func (x *GadgetEvent) GetPayload() []byte {
	if x != nil {
		return x.Payload
	}
	return nil
}

type GadgetControlRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Event:
	//	*GadgetControlRequest_RunRequest
	//	*GadgetControlRequest_StopRequest
	Event isGadgetControlRequest_Event `protobuf_oneof:"Event"`
}

func (x *GadgetControlRequest) Reset() {
	*x = GadgetControlRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_api_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GadgetControlRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GadgetControlRequest) ProtoMessage() {}

func (x *GadgetControlRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_api_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GadgetControlRequest.ProtoReflect.Descriptor instead.
func (*GadgetControlRequest) Descriptor() ([]byte, []int) {
	return file_api_api_proto_rawDescGZIP(), []int{4}
}

func (m *GadgetControlRequest) GetEvent() isGadgetControlRequest_Event {
	if m != nil {
		return m.Event
	}
	return nil
}

func (x *GadgetControlRequest) GetRunRequest() *GadgetRunRequest {
	if x, ok := x.GetEvent().(*GadgetControlRequest_RunRequest); ok {
		return x.RunRequest
	}
	return nil
}

func (x *GadgetControlRequest) GetStopRequest() *GadgetStopRequest {
	if x, ok := x.GetEvent().(*GadgetControlRequest_StopRequest); ok {
		return x.StopRequest
	}
	return nil
}

type isGadgetControlRequest_Event interface {
	isGadgetControlRequest_Event()
}

type GadgetControlRequest_RunRequest struct {
	RunRequest *GadgetRunRequest `protobuf:"bytes,1,opt,name=runRequest,proto3,oneof"`
}

type GadgetControlRequest_StopRequest struct {
	StopRequest *GadgetStopRequest `protobuf:"bytes,2,opt,name=stopRequest,proto3,oneof"`
}

func (*GadgetControlRequest_RunRequest) isGadgetControlRequest_Event() {}

func (*GadgetControlRequest_StopRequest) isGadgetControlRequest_Event() {}

type InfoRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Version string `protobuf:"bytes,1,opt,name=version,proto3" json:"version,omitempty"`
}

func (x *InfoRequest) Reset() {
	*x = InfoRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_api_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *InfoRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*InfoRequest) ProtoMessage() {}

func (x *InfoRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_api_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use InfoRequest.ProtoReflect.Descriptor instead.
func (*InfoRequest) Descriptor() ([]byte, []int) {
	return file_api_api_proto_rawDescGZIP(), []int{5}
}

func (x *InfoRequest) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

type InfoResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Version string `protobuf:"bytes,1,opt,name=version,proto3" json:"version,omitempty"`
	Catalog []byte `protobuf:"bytes,2,opt,name=catalog,proto3" json:"catalog,omitempty"`
}

func (x *InfoResponse) Reset() {
	*x = InfoResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_api_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *InfoResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*InfoResponse) ProtoMessage() {}

func (x *InfoResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_api_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use InfoResponse.ProtoReflect.Descriptor instead.
func (*InfoResponse) Descriptor() ([]byte, []int) {
	return file_api_api_proto_rawDescGZIP(), []int{6}
}

func (x *InfoResponse) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

func (x *InfoResponse) GetCatalog() []byte {
	if x != nil {
		return x.Catalog
	}
	return nil
}

type InstallPersistentGadgetRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RunRequest        *GadgetRunRequest `protobuf:"bytes,1,opt,name=runRequest,proto3" json:"runRequest,omitempty"`
	EventBufferLength int32             `protobuf:"varint,2,opt,name=eventBufferLength,proto3" json:"eventBufferLength,omitempty"`
}

func (x *InstallPersistentGadgetRequest) Reset() {
	*x = InstallPersistentGadgetRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_api_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *InstallPersistentGadgetRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*InstallPersistentGadgetRequest) ProtoMessage() {}

func (x *InstallPersistentGadgetRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_api_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use InstallPersistentGadgetRequest.ProtoReflect.Descriptor instead.
func (*InstallPersistentGadgetRequest) Descriptor() ([]byte, []int) {
	return file_api_api_proto_rawDescGZIP(), []int{7}
}

func (x *InstallPersistentGadgetRequest) GetRunRequest() *GadgetRunRequest {
	if x != nil {
		return x.RunRequest
	}
	return nil
}

func (x *InstallPersistentGadgetRequest) GetEventBufferLength() int32 {
	if x != nil {
		return x.EventBufferLength
	}
	return 0
}

type InstallPersistentGadgetResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Result int32  `protobuf:"varint,1,opt,name=result,proto3" json:"result,omitempty"`
	Id     string `protobuf:"bytes,2,opt,name=id,proto3" json:"id,omitempty"`
}

func (x *InstallPersistentGadgetResponse) Reset() {
	*x = InstallPersistentGadgetResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_api_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *InstallPersistentGadgetResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*InstallPersistentGadgetResponse) ProtoMessage() {}

func (x *InstallPersistentGadgetResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_api_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use InstallPersistentGadgetResponse.ProtoReflect.Descriptor instead.
func (*InstallPersistentGadgetResponse) Descriptor() ([]byte, []int) {
	return file_api_api_proto_rawDescGZIP(), []int{8}
}

func (x *InstallPersistentGadgetResponse) GetResult() int32 {
	if x != nil {
		return x.Result
	}
	return 0
}

func (x *InstallPersistentGadgetResponse) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

type ListPersistentGadgetRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *ListPersistentGadgetRequest) Reset() {
	*x = ListPersistentGadgetRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_api_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListPersistentGadgetRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListPersistentGadgetRequest) ProtoMessage() {}

func (x *ListPersistentGadgetRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_api_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListPersistentGadgetRequest.ProtoReflect.Descriptor instead.
func (*ListPersistentGadgetRequest) Descriptor() ([]byte, []int) {
	return file_api_api_proto_rawDescGZIP(), []int{9}
}

type ListPersistentGadgetResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PersistentGadgets []*GadgetRunRequest `protobuf:"bytes,1,rep,name=persistentGadgets,proto3" json:"persistentGadgets,omitempty"`
}

func (x *ListPersistentGadgetResponse) Reset() {
	*x = ListPersistentGadgetResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_api_proto_msgTypes[10]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListPersistentGadgetResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListPersistentGadgetResponse) ProtoMessage() {}

func (x *ListPersistentGadgetResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_api_proto_msgTypes[10]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListPersistentGadgetResponse.ProtoReflect.Descriptor instead.
func (*ListPersistentGadgetResponse) Descriptor() ([]byte, []int) {
	return file_api_api_proto_rawDescGZIP(), []int{10}
}

func (x *ListPersistentGadgetResponse) GetPersistentGadgets() []*GadgetRunRequest {
	if x != nil {
		return x.PersistentGadgets
	}
	return nil
}

type RemovePersistentGadgetRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
}

func (x *RemovePersistentGadgetRequest) Reset() {
	*x = RemovePersistentGadgetRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_api_proto_msgTypes[11]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RemovePersistentGadgetRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RemovePersistentGadgetRequest) ProtoMessage() {}

func (x *RemovePersistentGadgetRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_api_proto_msgTypes[11]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RemovePersistentGadgetRequest.ProtoReflect.Descriptor instead.
func (*RemovePersistentGadgetRequest) Descriptor() ([]byte, []int) {
	return file_api_api_proto_rawDescGZIP(), []int{11}
}

func (x *RemovePersistentGadgetRequest) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

type StatusResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Result int32 `protobuf:"varint,1,opt,name=result,proto3" json:"result,omitempty"`
}

func (x *StatusResponse) Reset() {
	*x = StatusResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_api_proto_msgTypes[12]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *StatusResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StatusResponse) ProtoMessage() {}

func (x *StatusResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_api_proto_msgTypes[12]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StatusResponse.ProtoReflect.Descriptor instead.
func (*StatusResponse) Descriptor() ([]byte, []int) {
	return file_api_api_proto_rawDescGZIP(), []int{12}
}

func (x *StatusResponse) GetResult() int32 {
	if x != nil {
		return x.Result
	}
	return 0
}

var File_api_api_proto protoreflect.FileDescriptor

var file_api_api_proto_rawDesc = []byte{
	0x0a, 0x0d, 0x61, 0x70, 0x69, 0x2f, 0x61, 0x70, 0x69, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x03, 0x61, 0x70, 0x69, 0x22, 0xb4, 0x02, 0x0a, 0x10, 0x47, 0x61, 0x64, 0x67, 0x65, 0x74, 0x52,
	0x75, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1e, 0x0a, 0x0a, 0x67, 0x61, 0x64,
	0x67, 0x65, 0x74, 0x4e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x67,
	0x61, 0x64, 0x67, 0x65, 0x74, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x26, 0x0a, 0x0e, 0x67, 0x61, 0x64,
	0x67, 0x65, 0x74, 0x43, 0x61, 0x74, 0x65, 0x67, 0x6f, 0x72, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x0e, 0x67, 0x61, 0x64, 0x67, 0x65, 0x74, 0x43, 0x61, 0x74, 0x65, 0x67, 0x6f, 0x72,
	0x79, 0x12, 0x39, 0x0a, 0x06, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28,
	0x0b, 0x32, 0x21, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x47, 0x61, 0x64, 0x67, 0x65, 0x74, 0x52, 0x75,
	0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x2e, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x73, 0x45,
	0x6e, 0x74, 0x72, 0x79, 0x52, 0x06, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x73, 0x12, 0x14, 0x0a, 0x05,
	0x6e, 0x6f, 0x64, 0x65, 0x73, 0x18, 0x0a, 0x20, 0x03, 0x28, 0x09, 0x52, 0x05, 0x6e, 0x6f, 0x64,
	0x65, 0x73, 0x12, 0x16, 0x0a, 0x06, 0x66, 0x61, 0x6e, 0x4f, 0x75, 0x74, 0x18, 0x0b, 0x20, 0x01,
	0x28, 0x08, 0x52, 0x06, 0x66, 0x61, 0x6e, 0x4f, 0x75, 0x74, 0x12, 0x1a, 0x0a, 0x08, 0x6c, 0x6f,
	0x67, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x08, 0x6c, 0x6f,
	0x67, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x12, 0x18, 0x0a, 0x07, 0x74, 0x69, 0x6d, 0x65, 0x6f, 0x75,
	0x74, 0x18, 0x0d, 0x20, 0x01, 0x28, 0x03, 0x52, 0x07, 0x74, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74,
	0x1a, 0x39, 0x0a, 0x0b, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12,
	0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65,
	0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x22, 0x13, 0x0a, 0x11, 0x47,
	0x61, 0x64, 0x67, 0x65, 0x74, 0x53, 0x74, 0x6f, 0x70, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x22, 0x25, 0x0a, 0x13, 0x47, 0x61, 0x64, 0x67, 0x65, 0x74, 0x41, 0x74, 0x74, 0x61, 0x63, 0x68,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x22, 0x4d, 0x0a, 0x0b, 0x47, 0x61, 0x64, 0x67, 0x65,
	0x74, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0d, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x10, 0x0a, 0x03, 0x73, 0x65,
	0x71, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x03, 0x73, 0x65, 0x71, 0x12, 0x18, 0x0a, 0x07,
	0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x70,
	0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x22, 0x94, 0x01, 0x0a, 0x14, 0x47, 0x61, 0x64, 0x67, 0x65,
	0x74, 0x43, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12,
	0x37, 0x0a, 0x0a, 0x72, 0x75, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x15, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x47, 0x61, 0x64, 0x67, 0x65, 0x74,
	0x52, 0x75, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x48, 0x00, 0x52, 0x0a, 0x72, 0x75,
	0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x3a, 0x0a, 0x0b, 0x73, 0x74, 0x6f, 0x70,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x16, 0x2e,
	0x61, 0x70, 0x69, 0x2e, 0x47, 0x61, 0x64, 0x67, 0x65, 0x74, 0x53, 0x74, 0x6f, 0x70, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x48, 0x00, 0x52, 0x0b, 0x73, 0x74, 0x6f, 0x70, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x42, 0x07, 0x0a, 0x05, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x22, 0x27, 0x0a,
	0x0b, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x18, 0x0a, 0x07,
	0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x76,
	0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x22, 0x42, 0x0a, 0x0c, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f,
	0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
	0x12, 0x18, 0x0a, 0x07, 0x63, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x07, 0x63, 0x61, 0x74, 0x61, 0x6c, 0x6f, 0x67, 0x22, 0x85, 0x01, 0x0a, 0x1e, 0x49,
	0x6e, 0x73, 0x74, 0x61, 0x6c, 0x6c, 0x50, 0x65, 0x72, 0x73, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x74,
	0x47, 0x61, 0x64, 0x67, 0x65, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x35, 0x0a,
	0x0a, 0x72, 0x75, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x15, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x47, 0x61, 0x64, 0x67, 0x65, 0x74, 0x52, 0x75,
	0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x52, 0x0a, 0x72, 0x75, 0x6e, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x12, 0x2c, 0x0a, 0x11, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x42, 0x75, 0x66,
	0x66, 0x65, 0x72, 0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x18, 0x02, 0x20, 0x01, 0x28, 0x05, 0x52,
	0x11, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x42, 0x75, 0x66, 0x66, 0x65, 0x72, 0x4c, 0x65, 0x6e, 0x67,
	0x74, 0x68, 0x22, 0x49, 0x0a, 0x1f, 0x49, 0x6e, 0x73, 0x74, 0x61, 0x6c, 0x6c, 0x50, 0x65, 0x72,
	0x73, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x74, 0x47, 0x61, 0x64, 0x67, 0x65, 0x74, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x05, 0x52, 0x06, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x12, 0x0e, 0x0a,
	0x02, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x22, 0x1d, 0x0a,
	0x1b, 0x4c, 0x69, 0x73, 0x74, 0x50, 0x65, 0x72, 0x73, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x74, 0x47,
	0x61, 0x64, 0x67, 0x65, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x22, 0x63, 0x0a, 0x1c,
	0x4c, 0x69, 0x73, 0x74, 0x50, 0x65, 0x72, 0x73, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x74, 0x47, 0x61,
	0x64, 0x67, 0x65, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x43, 0x0a, 0x11,
	0x70, 0x65, 0x72, 0x73, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x74, 0x47, 0x61, 0x64, 0x67, 0x65, 0x74,
	0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x15, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x47, 0x61,
	0x64, 0x67, 0x65, 0x74, 0x52, 0x75, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x52, 0x11,
	0x70, 0x65, 0x72, 0x73, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x74, 0x47, 0x61, 0x64, 0x67, 0x65, 0x74,
	0x73, 0x22, 0x2f, 0x0a, 0x1d, 0x52, 0x65, 0x6d, 0x6f, 0x76, 0x65, 0x50, 0x65, 0x72, 0x73, 0x69,
	0x73, 0x74, 0x65, 0x6e, 0x74, 0x47, 0x61, 0x64, 0x67, 0x65, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02,
	0x69, 0x64, 0x22, 0x28, 0x0a, 0x0e, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x05, 0x52, 0x06, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x32, 0xea, 0x03, 0x0a,
	0x0d, 0x47, 0x61, 0x64, 0x67, 0x65, 0x74, 0x4d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x12, 0x30,
	0x0a, 0x07, 0x47, 0x65, 0x74, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x10, 0x2e, 0x61, 0x70, 0x69, 0x2e,
	0x49, 0x6e, 0x66, 0x6f, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x11, 0x2e, 0x61, 0x70,
	0x69, 0x2e, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00,
	0x12, 0x3e, 0x0a, 0x09, 0x52, 0x75, 0x6e, 0x47, 0x61, 0x64, 0x67, 0x65, 0x74, 0x12, 0x19, 0x2e,
	0x61, 0x70, 0x69, 0x2e, 0x47, 0x61, 0x64, 0x67, 0x65, 0x74, 0x43, 0x6f, 0x6e, 0x74, 0x72, 0x6f,
	0x6c, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x10, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x47,
	0x61, 0x64, 0x67, 0x65, 0x74, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x22, 0x00, 0x28, 0x01, 0x30, 0x01,
	0x12, 0x66, 0x0a, 0x17, 0x49, 0x6e, 0x73, 0x74, 0x61, 0x6c, 0x6c, 0x50, 0x65, 0x72, 0x73, 0x69,
	0x73, 0x74, 0x65, 0x6e, 0x74, 0x47, 0x61, 0x64, 0x67, 0x65, 0x74, 0x12, 0x23, 0x2e, 0x61, 0x70,
	0x69, 0x2e, 0x49, 0x6e, 0x73, 0x74, 0x61, 0x6c, 0x6c, 0x50, 0x65, 0x72, 0x73, 0x69, 0x73, 0x74,
	0x65, 0x6e, 0x74, 0x47, 0x61, 0x64, 0x67, 0x65, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x1a, 0x24, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x49, 0x6e, 0x73, 0x74, 0x61, 0x6c, 0x6c, 0x50, 0x65,
	0x72, 0x73, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x74, 0x47, 0x61, 0x64, 0x67, 0x65, 0x74, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x5e, 0x0a, 0x15, 0x4c, 0x69, 0x73, 0x74,
	0x50, 0x65, 0x72, 0x73, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x74, 0x47, 0x61, 0x64, 0x67, 0x65, 0x74,
	0x73, 0x12, 0x20, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x4c, 0x69, 0x73, 0x74, 0x50, 0x65, 0x72, 0x73,
	0x69, 0x73, 0x74, 0x65, 0x6e, 0x74, 0x47, 0x61, 0x64, 0x67, 0x65, 0x74, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x1a, 0x21, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x4c, 0x69, 0x73, 0x74, 0x50, 0x65,
	0x72, 0x73, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x74, 0x47, 0x61, 0x64, 0x67, 0x65, 0x74, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x53, 0x0a, 0x16, 0x52, 0x65, 0x6d, 0x6f,
	0x76, 0x65, 0x50, 0x65, 0x72, 0x73, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x74, 0x47, 0x61, 0x64, 0x67,
	0x65, 0x74, 0x12, 0x22, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x52, 0x65, 0x6d, 0x6f, 0x76, 0x65, 0x50,
	0x65, 0x72, 0x73, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x74, 0x47, 0x61, 0x64, 0x67, 0x65, 0x74, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x13, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x53, 0x74, 0x61,
	0x74, 0x75, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x4a, 0x0a,
	0x18, 0x41, 0x74, 0x74, 0x61, 0x63, 0x68, 0x54, 0x6f, 0x50, 0x65, 0x72, 0x73, 0x69, 0x73, 0x74,
	0x65, 0x6e, 0x74, 0x47, 0x61, 0x64, 0x67, 0x65, 0x74, 0x12, 0x18, 0x2e, 0x61, 0x70, 0x69, 0x2e,
	0x47, 0x61, 0x64, 0x67, 0x65, 0x74, 0x41, 0x74, 0x74, 0x61, 0x63, 0x68, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x1a, 0x10, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x47, 0x61, 0x64, 0x67, 0x65, 0x74,
	0x45, 0x76, 0x65, 0x6e, 0x74, 0x22, 0x00, 0x30, 0x01, 0x42, 0x45, 0x5a, 0x43, 0x67, 0x69, 0x74,
	0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x69, 0x6e, 0x73, 0x70, 0x65, 0x6b, 0x74, 0x6f,
	0x72, 0x2d, 0x67, 0x61, 0x64, 0x67, 0x65, 0x74, 0x2f, 0x69, 0x6e, 0x73, 0x70, 0x65, 0x6b, 0x74,
	0x6f, 0x72, 0x2d, 0x67, 0x61, 0x64, 0x67, 0x65, 0x74, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x67, 0x61,
	0x64, 0x67, 0x65, 0x74, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2f, 0x61, 0x70, 0x69,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_api_api_proto_rawDescOnce sync.Once
	file_api_api_proto_rawDescData = file_api_api_proto_rawDesc
)

func file_api_api_proto_rawDescGZIP() []byte {
	file_api_api_proto_rawDescOnce.Do(func() {
		file_api_api_proto_rawDescData = protoimpl.X.CompressGZIP(file_api_api_proto_rawDescData)
	})
	return file_api_api_proto_rawDescData
}

var file_api_api_proto_msgTypes = make([]protoimpl.MessageInfo, 14)
var file_api_api_proto_goTypes = []interface{}{
	(*GadgetRunRequest)(nil),                // 0: api.GadgetRunRequest
	(*GadgetStopRequest)(nil),               // 1: api.GadgetStopRequest
	(*GadgetAttachRequest)(nil),             // 2: api.GadgetAttachRequest
	(*GadgetEvent)(nil),                     // 3: api.GadgetEvent
	(*GadgetControlRequest)(nil),            // 4: api.GadgetControlRequest
	(*InfoRequest)(nil),                     // 5: api.InfoRequest
	(*InfoResponse)(nil),                    // 6: api.InfoResponse
	(*InstallPersistentGadgetRequest)(nil),  // 7: api.InstallPersistentGadgetRequest
	(*InstallPersistentGadgetResponse)(nil), // 8: api.InstallPersistentGadgetResponse
	(*ListPersistentGadgetRequest)(nil),     // 9: api.ListPersistentGadgetRequest
	(*ListPersistentGadgetResponse)(nil),    // 10: api.ListPersistentGadgetResponse
	(*RemovePersistentGadgetRequest)(nil),   // 11: api.RemovePersistentGadgetRequest
	(*StatusResponse)(nil),                  // 12: api.StatusResponse
	nil,                                     // 13: api.GadgetRunRequest.ParamsEntry
}
var file_api_api_proto_depIdxs = []int32{
	13, // 0: api.GadgetRunRequest.params:type_name -> api.GadgetRunRequest.ParamsEntry
	0,  // 1: api.GadgetControlRequest.runRequest:type_name -> api.GadgetRunRequest
	1,  // 2: api.GadgetControlRequest.stopRequest:type_name -> api.GadgetStopRequest
	0,  // 3: api.InstallPersistentGadgetRequest.runRequest:type_name -> api.GadgetRunRequest
	0,  // 4: api.ListPersistentGadgetResponse.persistentGadgets:type_name -> api.GadgetRunRequest
	5,  // 5: api.GadgetManager.GetInfo:input_type -> api.InfoRequest
	4,  // 6: api.GadgetManager.RunGadget:input_type -> api.GadgetControlRequest
	7,  // 7: api.GadgetManager.InstallPersistentGadget:input_type -> api.InstallPersistentGadgetRequest
	9,  // 8: api.GadgetManager.ListPersistentGadgets:input_type -> api.ListPersistentGadgetRequest
	11, // 9: api.GadgetManager.RemovePersistentGadget:input_type -> api.RemovePersistentGadgetRequest
	2,  // 10: api.GadgetManager.AttachToPersistentGadget:input_type -> api.GadgetAttachRequest
	6,  // 11: api.GadgetManager.GetInfo:output_type -> api.InfoResponse
	3,  // 12: api.GadgetManager.RunGadget:output_type -> api.GadgetEvent
	8,  // 13: api.GadgetManager.InstallPersistentGadget:output_type -> api.InstallPersistentGadgetResponse
	10, // 14: api.GadgetManager.ListPersistentGadgets:output_type -> api.ListPersistentGadgetResponse
	12, // 15: api.GadgetManager.RemovePersistentGadget:output_type -> api.StatusResponse
	3,  // 16: api.GadgetManager.AttachToPersistentGadget:output_type -> api.GadgetEvent
	11, // [11:17] is the sub-list for method output_type
	5,  // [5:11] is the sub-list for method input_type
	5,  // [5:5] is the sub-list for extension type_name
	5,  // [5:5] is the sub-list for extension extendee
	0,  // [0:5] is the sub-list for field type_name
}

func init() { file_api_api_proto_init() }
func file_api_api_proto_init() {
	if File_api_api_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_api_api_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GadgetRunRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_api_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GadgetStopRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_api_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GadgetAttachRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_api_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GadgetEvent); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_api_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GadgetControlRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_api_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*InfoRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_api_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*InfoResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_api_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*InstallPersistentGadgetRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_api_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*InstallPersistentGadgetResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_api_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ListPersistentGadgetRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_api_proto_msgTypes[10].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ListPersistentGadgetResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_api_proto_msgTypes[11].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RemovePersistentGadgetRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_api_proto_msgTypes[12].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*StatusResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_api_api_proto_msgTypes[4].OneofWrappers = []interface{}{
		(*GadgetControlRequest_RunRequest)(nil),
		(*GadgetControlRequest_StopRequest)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_api_api_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   14,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_api_api_proto_goTypes,
		DependencyIndexes: file_api_api_proto_depIdxs,
		MessageInfos:      file_api_api_proto_msgTypes,
	}.Build()
	File_api_api_proto = out.File
	file_api_api_proto_rawDesc = nil
	file_api_api_proto_goTypes = nil
	file_api_api_proto_depIdxs = nil
}
