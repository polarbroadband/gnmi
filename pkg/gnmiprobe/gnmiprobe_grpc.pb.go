// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package gnmiprobe

import (
	context "context"
	gnmi "github.com/openconfig/gnmi/proto/gnmi"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// ProbeClient is the client API for Probe service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ProbeClient interface {
	// healthckeck
	Healtz(ctx context.Context, in *HealtzReq, opts ...grpc.CallOption) (*SvrStat, error)
	// get gNMI Probe target capabilities
	GetCapability(ctx context.Context, in *ProbeRequest, opts ...grpc.CallOption) (*gnmi.CapabilityResponse, error)
	// gNMI Probe request and response data stream
	ConnectProbe(ctx context.Context, opts ...grpc.CallOption) (Probe_ConnectProbeClient, error)
}

type probeClient struct {
	cc grpc.ClientConnInterface
}

func NewProbeClient(cc grpc.ClientConnInterface) ProbeClient {
	return &probeClient{cc}
}

func (c *probeClient) Healtz(ctx context.Context, in *HealtzReq, opts ...grpc.CallOption) (*SvrStat, error) {
	out := new(SvrStat)
	err := c.cc.Invoke(ctx, "/gnmiprobe.Probe/Healtz", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *probeClient) GetCapability(ctx context.Context, in *ProbeRequest, opts ...grpc.CallOption) (*gnmi.CapabilityResponse, error) {
	out := new(gnmi.CapabilityResponse)
	err := c.cc.Invoke(ctx, "/gnmiprobe.Probe/GetCapability", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *probeClient) ConnectProbe(ctx context.Context, opts ...grpc.CallOption) (Probe_ConnectProbeClient, error) {
	stream, err := c.cc.NewStream(ctx, &Probe_ServiceDesc.Streams[0], "/gnmiprobe.Probe/ConnectProbe", opts...)
	if err != nil {
		return nil, err
	}
	x := &probeConnectProbeClient{stream}
	return x, nil
}

type Probe_ConnectProbeClient interface {
	Send(*ProbeRequest) error
	Recv() (*ProbeResponse, error)
	grpc.ClientStream
}

type probeConnectProbeClient struct {
	grpc.ClientStream
}

func (x *probeConnectProbeClient) Send(m *ProbeRequest) error {
	return x.ClientStream.SendMsg(m)
}

func (x *probeConnectProbeClient) Recv() (*ProbeResponse, error) {
	m := new(ProbeResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// ProbeServer is the server API for Probe service.
// All implementations must embed UnimplementedProbeServer
// for forward compatibility
type ProbeServer interface {
	// healthckeck
	Healtz(context.Context, *HealtzReq) (*SvrStat, error)
	// get gNMI Probe target capabilities
	GetCapability(context.Context, *ProbeRequest) (*gnmi.CapabilityResponse, error)
	// gNMI Probe request and response data stream
	ConnectProbe(Probe_ConnectProbeServer) error
	mustEmbedUnimplementedProbeServer()
}

// UnimplementedProbeServer must be embedded to have forward compatible implementations.
type UnimplementedProbeServer struct {
}

func (UnimplementedProbeServer) Healtz(context.Context, *HealtzReq) (*SvrStat, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Healtz not implemented")
}
func (UnimplementedProbeServer) GetCapability(context.Context, *ProbeRequest) (*gnmi.CapabilityResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetCapability not implemented")
}
func (UnimplementedProbeServer) ConnectProbe(Probe_ConnectProbeServer) error {
	return status.Errorf(codes.Unimplemented, "method ConnectProbe not implemented")
}
func (UnimplementedProbeServer) mustEmbedUnimplementedProbeServer() {}

// UnsafeProbeServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ProbeServer will
// result in compilation errors.
type UnsafeProbeServer interface {
	mustEmbedUnimplementedProbeServer()
}

func RegisterProbeServer(s grpc.ServiceRegistrar, srv ProbeServer) {
	s.RegisterService(&Probe_ServiceDesc, srv)
}

func _Probe_Healtz_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(HealtzReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ProbeServer).Healtz(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/gnmiprobe.Probe/Healtz",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ProbeServer).Healtz(ctx, req.(*HealtzReq))
	}
	return interceptor(ctx, in, info, handler)
}

func _Probe_GetCapability_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ProbeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ProbeServer).GetCapability(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/gnmiprobe.Probe/GetCapability",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ProbeServer).GetCapability(ctx, req.(*ProbeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Probe_ConnectProbe_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(ProbeServer).ConnectProbe(&probeConnectProbeServer{stream})
}

type Probe_ConnectProbeServer interface {
	Send(*ProbeResponse) error
	Recv() (*ProbeRequest, error)
	grpc.ServerStream
}

type probeConnectProbeServer struct {
	grpc.ServerStream
}

func (x *probeConnectProbeServer) Send(m *ProbeResponse) error {
	return x.ServerStream.SendMsg(m)
}

func (x *probeConnectProbeServer) Recv() (*ProbeRequest, error) {
	m := new(ProbeRequest)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// Probe_ServiceDesc is the grpc.ServiceDesc for Probe service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Probe_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "gnmiprobe.Probe",
	HandlerType: (*ProbeServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Healtz",
			Handler:    _Probe_Healtz_Handler,
		},
		{
			MethodName: "GetCapability",
			Handler:    _Probe_GetCapability_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "ConnectProbe",
			Handler:       _Probe_ConnectProbe_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "gnmiprobe.proto",
}
