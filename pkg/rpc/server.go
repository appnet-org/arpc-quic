package rpc

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/appnet-org/arpc-quic/pkg/packet"
	"github.com/appnet-org/arpc-quic/pkg/transport"
	"github.com/appnet-org/arpc/pkg/logging"
	"github.com/appnet-org/arpc/pkg/serializer"
	"github.com/quic-go/quic-go"
	"go.uber.org/zap"
)

// MethodHandler defines the function signature for handling an RPC method.
type MethodHandler func(srv any, ctx context.Context, dec func(any) error) (resp any, err error)

// MethodDesc represents an RPC service's method specification.
type MethodDesc struct {
	MethodName string
	Handler    MethodHandler
}

// ServiceDesc describes an RPC service, including its implementation and methods.
type ServiceDesc struct {
	ServiceImpl any
	ServiceName string
	Methods     map[string]*MethodDesc
}

// Server is the core RPC server handling transport, serialization, and registered services.
type Server struct {
	transport  *transport.QUICTransport
	serializer serializer.Serializer
	services   map[string]*ServiceDesc
}

// NewServer initializes a new Server instance with the given address and serializer.
func NewServer(addr string, serializer serializer.Serializer) (*Server, error) {
	quicTransport, err := transport.NewQUICTransport(addr)
	if err != nil {
		return nil, err
	}
	return &Server{
		transport:  quicTransport,
		serializer: serializer,
		services:   make(map[string]*ServiceDesc),
	}, nil
}

// RegisterService registers a service and its methods with the server.
func (s *Server) RegisterService(desc *ServiceDesc, impl any) {
	s.services[desc.ServiceName] = desc
	logging.Info("Registered service", zap.String("serviceName", desc.ServiceName))
}

// parseFramedRequest extracts service, method, and payload segments from a request frame.
// Wire format: [dst ip(4B)][dst port(2B)][src port(2B)][serviceLen(2B)][service][methodLen(2B)][method][payload]
func (s *Server) parseFramedRequest(data []byte) (string, string, []byte, error) {
	offset := 0

	// Service
	if offset+2 > len(data) {
		return "", "", nil, fmt.Errorf("data too short for service length")
	}
	serviceLen := int(binary.LittleEndian.Uint16(data[offset:]))
	offset += 2
	if offset+serviceLen > len(data) {
		return "", "", nil, fmt.Errorf("service length %d exceeds data length", serviceLen)
	}
	service := string(data[offset : offset+serviceLen])
	offset += serviceLen

	// Method
	if offset+2 > len(data) {
		return "", "", nil, fmt.Errorf("data too short for method length")
	}
	methodLen := int(binary.LittleEndian.Uint16(data[offset:]))
	offset += 2
	if offset+methodLen > len(data) {
		return "", "", nil, fmt.Errorf("method length %d exceeds data length", methodLen)
	}
	method := string(data[offset : offset+methodLen])
	offset += methodLen

	// Payload
	payload := data[offset:]

	return service, method, payload, nil
}

// frameResponse constructs a binary message with
// [serviceLen(2B)][service][methodLen(2B)][method][payload]
func (s *Server) frameResponse(service, method string, payload []byte) ([]byte, error) {
	// total size = 2 + len(service) + 2 + len(method) + len(payload)
	totalSize := 4 + len(service) + len(method) + len(payload)
	buf := make([]byte, totalSize)

	// service length
	binary.LittleEndian.PutUint16(buf[0:2], uint16(len(service)))
	copy(buf[2:], service)

	// method length
	methodStart := 2 + len(service)
	binary.LittleEndian.PutUint16(buf[methodStart:methodStart+2], uint16(len(method)))
	copy(buf[methodStart+2:], method)

	// payload
	payloadStart := methodStart + 2 + len(method)
	copy(buf[payloadStart:], payload)

	return buf, nil
}

// Start begins listening for incoming RPC requests, dispatching to the appropriate service/method handler.
func (s *Server) Start() {
	logging.Info("Server started... Waiting for connections.")

	for {
		// Accept a new QUIC connection
		conn, err := s.transport.AcceptConnection()
		if err != nil {
			logging.Error("Error accepting connection", zap.Error(err))
			continue
		}

		logging.Info("New client connected", zap.String("addr", conn.RemoteAddr().String()))

		// Handle each connection in a separate goroutine
		go s.handleConnection(conn)
	}
}

// handleConnection handles a single QUIC connection
func (s *Server) handleConnection(conn quic.Connection) {
	defer conn.CloseWithError(0, "server closing connection")

	// Create a transport instance for this connection
	connTransport := transport.NewQUICTransportForConnection(conn, s.transport.GetResolver())

	for {
		// Receive a packet from the client
		data, addr, rpcID, _, err := connTransport.Receive(packet.MaxQUICPayloadSize)
		if err != nil {
			if err == io.EOF {
				logging.Info("Client disconnected", zap.String("addr", conn.RemoteAddr().String()))
			} else {
				logging.Error("Error receiving data", zap.Error(err))
			}
			return
		}

		if data == nil {
			continue // Either still waiting for fragments or we received an non-data packet
		}

		// Parse request payload
		serviceName, methodName, reqPayloadBytes, err := s.parseFramedRequest(data)
		if err != nil {
			logging.Error("Failed to parse framed request", zap.Error(err))
			if err := connTransport.Send(addr.String(), rpcID, []byte(err.Error()), packet.PacketTypeUnknown); err != nil {
				logging.Error("Error sending error response", zap.Error(err))
			}
			continue
		}

		// Create context
		ctx := context.Background()

		// Lookup service and method
		svcDesc, ok := s.services[serviceName]
		if !ok {
			logging.Warn("Unknown service", zap.String("serviceName", serviceName))
			if err := connTransport.Send(addr.String(), rpcID, []byte("unknown service"), packet.PacketTypeError); err != nil {
				logging.Error("Error sending error response", zap.Error(err))
			}
			continue
		}
		methodDesc, ok := svcDesc.Methods[methodName]
		if !ok {
			logging.Warn("Unknown method",
				zap.String("serviceName", serviceName),
				zap.String("methodName", methodName))
			continue
		}

		// Invoke method handler
		resp, err := methodDesc.Handler(svcDesc.ServiceImpl, ctx, func(v any) error {
			return s.serializer.Unmarshal(reqPayloadBytes, v)
		})
		if err != nil {
			var errType packet.PacketTypeID
			if rpcErr, ok := err.(*RPCError); ok && rpcErr.Type == RPCFailError {
				errType = packet.PacketTypeError
			} else {
				errType = packet.PacketTypeUnknown
				logging.Error("Handler error", zap.Error(err))
			}
			if err := connTransport.Send(addr.String(), rpcID, []byte(err.Error()), errType); err != nil {
				logging.Error("Error sending error response", zap.Error(err))
			}
			continue
		}

		// Serialize response
		respPayloadBytes, err := s.serializer.Marshal(resp)
		if err != nil {
			logging.Error("Error marshaling response", zap.Error(err))
			if err := connTransport.Send(addr.String(), rpcID, []byte(err.Error()), packet.PacketTypeUnknown); err != nil {
				logging.Error("Error sending error response", zap.Error(err))
			}
			continue
		}

		// Frame response
		framedResp, err := s.frameResponse(serviceName, methodName, respPayloadBytes)
		if err != nil {
			logging.Error("Failed to frame response", zap.Error(err))
			if err := connTransport.Send(addr.String(), rpcID, []byte(err.Error()), packet.PacketTypeUnknown); err != nil {
				logging.Error("Error sending error response", zap.Error(err))
			}
			continue
		}

		// Send the response
		err = connTransport.Send(addr.String(), rpcID, framedResp, packet.PacketTypeData)
		if err != nil {
			logging.Error("Error sending response", zap.Error(err))
		}
	}
}

// GetTransport returns the underlying transport for advanced operations
func (s *Server) GetTransport() *transport.QUICTransport {
	return s.transport
}
