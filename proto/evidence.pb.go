// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        v3.21.12
// source: evidence.proto

package proto

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	structpb "google.golang.org/protobuf/types/known/structpb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type EvidenceContext struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	TenantId       string           `protobuf:"bytes,1,opt,name=tenant_id,json=tenant-id,proto3" json:"tenant_id,omitempty"`
	TrustAnchorIds []string         `protobuf:"bytes,2,rep,name=trust_anchor_ids,json=trust-anchor-ids,proto3" json:"trust_anchor_ids,omitempty"`
	ReferenceIds   []string         `protobuf:"bytes,3,rep,name=reference_ids,json=reference-ids,proto3" json:"reference_ids,omitempty"`
	Evidence       *structpb.Struct `protobuf:"bytes,5,opt,name=evidence,proto3" json:"evidence,omitempty"`
}

func (x *EvidenceContext) Reset() {
	*x = EvidenceContext{}
	if protoimpl.UnsafeEnabled {
		mi := &file_evidence_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EvidenceContext) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EvidenceContext) ProtoMessage() {}

func (x *EvidenceContext) ProtoReflect() protoreflect.Message {
	mi := &file_evidence_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EvidenceContext.ProtoReflect.Descriptor instead.
func (*EvidenceContext) Descriptor() ([]byte, []int) {
	return file_evidence_proto_rawDescGZIP(), []int{0}
}

func (x *EvidenceContext) GetTenantId() string {
	if x != nil {
		return x.TenantId
	}
	return ""
}

func (x *EvidenceContext) GetTrustAnchorIds() []string {
	if x != nil {
		return x.TrustAnchorIds
	}
	return nil
}

func (x *EvidenceContext) GetReferenceIds() []string {
	if x != nil {
		return x.ReferenceIds
	}
	return nil
}

func (x *EvidenceContext) GetEvidence() *structpb.Struct {
	if x != nil {
		return x.Evidence
	}
	return nil
}

var File_evidence_proto protoreflect.FileDescriptor

var file_evidence_proto_rawDesc = []byte{
	0x0a, 0x0e, 0x65, 0x76, 0x69, 0x64, 0x65, 0x6e, 0x63, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x05, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xb6, 0x01, 0x0a, 0x0f, 0x45, 0x76, 0x69, 0x64, 0x65, 0x6e,
	0x63, 0x65, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x12, 0x1c, 0x0a, 0x09, 0x74, 0x65, 0x6e,
	0x61, 0x6e, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x74, 0x65,
	0x6e, 0x61, 0x6e, 0x74, 0x2d, 0x69, 0x64, 0x12, 0x2a, 0x0a, 0x10, 0x74, 0x72, 0x75, 0x73, 0x74,
	0x5f, 0x61, 0x6e, 0x63, 0x68, 0x6f, 0x72, 0x5f, 0x69, 0x64, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28,
	0x09, 0x52, 0x10, 0x74, 0x72, 0x75, 0x73, 0x74, 0x2d, 0x61, 0x6e, 0x63, 0x68, 0x6f, 0x72, 0x2d,
	0x69, 0x64, 0x73, 0x12, 0x24, 0x0a, 0x0d, 0x72, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63, 0x65,
	0x5f, 0x69, 0x64, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0d, 0x72, 0x65, 0x66, 0x65,
	0x72, 0x65, 0x6e, 0x63, 0x65, 0x2d, 0x69, 0x64, 0x73, 0x12, 0x33, 0x0a, 0x08, 0x65, 0x76, 0x69,
	0x64, 0x65, 0x6e, 0x63, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74,
	0x72, 0x75, 0x63, 0x74, 0x52, 0x08, 0x65, 0x76, 0x69, 0x64, 0x65, 0x6e, 0x63, 0x65, 0x42, 0x24,
	0x5a, 0x22, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x76, 0x65, 0x72,
	0x61, 0x69, 0x73, 0x6f, 0x6e, 0x2f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2f, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_evidence_proto_rawDescOnce sync.Once
	file_evidence_proto_rawDescData = file_evidence_proto_rawDesc
)

func file_evidence_proto_rawDescGZIP() []byte {
	file_evidence_proto_rawDescOnce.Do(func() {
		file_evidence_proto_rawDescData = protoimpl.X.CompressGZIP(file_evidence_proto_rawDescData)
	})
	return file_evidence_proto_rawDescData
}

var file_evidence_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_evidence_proto_goTypes = []interface{}{
	(*EvidenceContext)(nil), // 0: proto.EvidenceContext
	(*structpb.Struct)(nil), // 1: google.protobuf.Struct
}
var file_evidence_proto_depIdxs = []int32{
	1, // 0: proto.EvidenceContext.evidence:type_name -> google.protobuf.Struct
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_evidence_proto_init() }
func file_evidence_proto_init() {
	if File_evidence_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_evidence_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EvidenceContext); i {
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
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_evidence_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_evidence_proto_goTypes,
		DependencyIndexes: file_evidence_proto_depIdxs,
		MessageInfos:      file_evidence_proto_msgTypes,
	}.Build()
	File_evidence_proto = out.File
	file_evidence_proto_rawDesc = nil
	file_evidence_proto_goTypes = nil
	file_evidence_proto_depIdxs = nil
}
