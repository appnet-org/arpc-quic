// pkg/rpc/client.go
package rpc

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/appnet-org/arpc-quic/pkg/logging"
	"github.com/appnet-org/arpc-quic/pkg/packet"
	"github.com/appnet-org/arpc-quic/pkg/serializer"
	"github.com/appnet-org/arpc-quic/pkg/transport"
	"go.uber.org/zap"
)

// Client represents an RPC client with a transport and serializer.
type Client struct {
	transport   *transport.QUICTransport
	serializer  serializer.Serializer
	defaultAddr string
}

// NewClient creates a new Client using the given serializer and target address.
// The client will create a QUIC connection to the server.
func NewClient(serializer serializer.Serializer, addr string) (*Client, error) {
	t, err := transport.NewQUICClientTransport()
	if err != nil {
		return nil, err
	}
	return &Client{
		transport:   t,
		serializer:  serializer,
		defaultAddr: addr,
	}, nil
}

// NewClientWithLocalAddr creates a new Client using the given serializer, target address, and local address.
// Note: For QUIC, the local address is not used in the same way as UDP.
// This function is kept for API compatibility but the localAddr parameter is ignored.
func NewClientWithLocalAddr(serializer serializer.Serializer, addr, localAddr string) (*Client, error) {
	// For QUIC, we don't bind to a local address in the same way
	// The OS will assign a local port when we connect
	return NewClient(serializer, addr)
}

// Transport returns the underlying QUIC transport for cleanup purposes
func (c *Client) Transport() *transport.QUICTransport {
	return c.transport
}

// frameRequest constructs a binary message with
// [serviceLen(2B)][service][methodLen(2B)][method][payload]
func (c *Client) frameRequest(service, method string, payload []byte) ([]byte, error) {
	// Pre-calculate buffer size (headers: 2 + 2 = 4 bytes)
	totalSize := 4 + len(service) + len(method) + len(payload)
	buf := make([]byte, totalSize)

	// service
	binary.LittleEndian.PutUint16(buf[0:2], uint16(len(service)))
	copy(buf[2:], service)

	// method
	methodStart := 2 + len(service)
	binary.LittleEndian.PutUint16(buf[methodStart:methodStart+2], uint16(len(method)))
	copy(buf[methodStart+2:], method)

	// payload
	payloadStart := methodStart + 2 + len(method)
	copy(buf[payloadStart:], payload)

	return buf, nil
}

func (c *Client) parseFramedResponse(data []byte) (service string, method string, payload []byte, err error) {
	offset := 0

	// Parse service name
	if len(data) < 2 {
		return "", "", nil, fmt.Errorf("invalid response (too short for serviceLen)")
	}
	serviceLen := int(binary.LittleEndian.Uint16(data[offset:]))
	offset += 2
	if offset+serviceLen > len(data) {
		return "", "", nil, fmt.Errorf("invalid response (truncated service)")
	}
	service = string(data[offset : offset+serviceLen])
	offset += serviceLen

	// Parse method name
	if offset+2 > len(data) {
		return "", "", nil, fmt.Errorf("invalid response (too short for methodLen)")
	}
	methodLen := int(binary.LittleEndian.Uint16(data[offset:]))
	offset += 2
	if offset+methodLen > len(data) {
		return "", "", nil, fmt.Errorf("invalid response (truncated method)")
	}
	method = string(data[offset : offset+methodLen])
	offset += methodLen

	payload = data[offset:]
	return service, method, payload, nil
}

func (c *Client) handleErrorPacket(errMsg string, errType packet.PacketTypeID) error {
	var rpcErrType RPCErrorType
	if errType == packet.PacketTypeError {
		rpcErrType = RPCFailError
	} else {
		rpcErrType = RPCUnknownError
	}
	return &RPCError{Type: rpcErrType, Reason: errMsg}
}

func (c *Client) handleResponsePacket(data []byte, rpcID uint64, resp any) error {
	// Parse framed response: extract service, method, payload
	_, _, respPayloadBytes, err := c.parseFramedResponse(data)
	if err != nil {
		return fmt.Errorf("failed to parse framed response: %w", err)
	}

	// Deserialize the response into resp
	if err := c.serializer.Unmarshal(respPayloadBytes, resp); err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}

	logging.Debug("Successfully received response", zap.Uint64("rpcID", rpcID))

	return nil
}

// Call makes an RPC call
func (c *Client) Call(ctx context.Context, service, method string, req any, resp any) error {
	rpcReqID := transport.GenerateRPCID()

	// Serialize the request payload
	reqPayloadBytes, err := c.serializer.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	// Frame the request into binary format
	framedReq, err := c.frameRequest(service, method, reqPayloadBytes)
	if err != nil {
		return fmt.Errorf("failed to frame request: %w", err)
	}

	// Send the framed request
	if err := c.transport.Send(c.defaultAddr, rpcReqID, framedReq, packet.PacketTypeData); err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}

	// Wait and process the response
	for {
		data, _, respID, packetTypeID, err := c.transport.Receive(packet.MaxQUICPayloadSize)
		if err != nil {
			return fmt.Errorf("failed to receive response: %w", err)
		}

		if data == nil {
			continue // Either still waiting for fragments or we received an non-data/error packet
		}

		if respID != rpcReqID {
			logging.Debug("Ignoring response with mismatched RPC ID",
				zap.Uint64("receivedID", respID),
				zap.Uint64("expectedID", rpcReqID))
			continue
		}

		// Process the packet based on its type
		switch packetTypeID {
		case packet.PacketTypeData:
			return c.handleResponsePacket(data, respID, resp)
		case packet.PacketTypeError, packet.PacketTypeUnknown:
			return c.handleErrorPacket(string(data), packetTypeID)
		default:
			logging.Debug("Ignoring packet with unknown type", zap.Uint8("packetTypeID", uint8(packetTypeID)))
			continue
		}
	}
}

// GetTransport returns the underlying transport for advanced operations
func (c *Client) GetTransport() *transport.QUICTransport {
	return c.transport
}
