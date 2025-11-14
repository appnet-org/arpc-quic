// This file defines the builtin packets (Request, Response, Error) and their corresponding
// serialization/deserialization codecs.
package packet

import (
	"encoding/binary"
	"errors"
)

// DataPacketCodec and ErrorPacketCodec are the codecs for data and error packets
var (
	dataPacketCodec  = &DataPacketCodec{}
	errorPacketCodec = &ErrorPacketCodec{}
)

// DataPacket represents a data packet (used for requests and responses)
type DataPacket struct {
	RPCID        uint64  // Unique RPC ID
	TotalPackets uint16  // Total number of packets in this RPC
	SeqNumber    uint16  // Sequence number of this packet
	DstIP        [4]byte // Destination IP address (4 bytes)
	DstPort      uint16  // Destination port
	SrcIP        [4]byte // Source IP address (4 bytes)
	SrcPort      uint16  // Source port
	Payload      []byte  // Partial application data
}

// ErrorPacket represents an error packet
type ErrorPacket struct {
	RPCID    uint64 // RPC ID that caused the error
	ErrorMsg string // Error message string
}

// DataPacketCodec implements DataPacket serialization for both Request and Response packets
type DataPacketCodec struct{}

// Serialize encodes a DataPacket into binary format:
// [PacketTypeID(1B)][RPCID(8B)][TotalPackets(2B)][SeqNumber(2B)][DstIP(4B)][DstPort(2B)][SrcIP(4B)][SrcPort(2B)][PayloadLen(4B)][Payload]
func (c *DataPacketCodec) Serialize(packet any) ([]byte, error) {
	p, ok := packet.(*DataPacket)
	if !ok {
		return nil, errors.New("invalid packet type for DataPacket codec")
	}

	payloadLen := len(p.Payload)
	totalSize := 29 + payloadLen // 1+8+2+2+4+2+4+2+4 = 29 bytes for header
	buf := make([]byte, totalSize)

	// Write packet type ID (always PacketTypeData for data packets)
	buf[0] = byte(PacketTypeData)
	binary.LittleEndian.PutUint64(buf[1:9], p.RPCID)
	binary.LittleEndian.PutUint16(buf[9:11], p.TotalPackets)
	binary.LittleEndian.PutUint16(buf[11:13], p.SeqNumber)

	// Copy destination IP (4 bytes)
	copy(buf[13:17], p.DstIP[:])

	// Write destination port
	binary.LittleEndian.PutUint16(buf[17:19], p.DstPort)

	// Copy source IP (4 bytes)
	copy(buf[19:23], p.SrcIP[:])

	// Write source port
	binary.LittleEndian.PutUint16(buf[23:25], p.SrcPort)

	// Write payload length
	binary.LittleEndian.PutUint32(buf[25:29], uint32(payloadLen))

	// Copy payload
	copy(buf[29:], p.Payload)

	return buf, nil
}

// Deserialize decodes binary data into a DataPacket
// Format: [PacketTypeID(1B)][RPCID(8B)][TotalPackets(2B)][SeqNumber(2B)][DstIP(4B)][DstPort(2B)][SrcIP(4B)][SrcPort(2B)][PayloadLen(4B)][Payload]
func (c *DataPacketCodec) Deserialize(data []byte) (any, error) {
	if len(data) < 29 {
		return nil, errors.New("data too short for DataPacket header")
	}

	p := &DataPacket{}
	// Skip packet type ID (first byte) - we know it's a data packet
	p.RPCID = binary.LittleEndian.Uint64(data[1:9])
	p.TotalPackets = binary.LittleEndian.Uint16(data[9:11])
	p.SeqNumber = binary.LittleEndian.Uint16(data[11:13])

	// Copy destination IP (4 bytes)
	copy(p.DstIP[:], data[13:17])

	// Read destination port
	p.DstPort = binary.LittleEndian.Uint16(data[17:19])

	// Copy source IP (4 bytes)
	copy(p.SrcIP[:], data[19:23])

	// Read source port
	p.SrcPort = binary.LittleEndian.Uint16(data[23:25])

	// Read payload length
	payloadLen := binary.LittleEndian.Uint32(data[25:29])

	// Validate length
	if len(data) < 29+int(payloadLen) {
		return nil, errors.New("data too short for declared payload length")
	}

	// Payload — copy if you need ownership, or slice directly for zero-copy
	p.Payload = data[29 : 29+payloadLen]

	return p, nil
}

// ErrorPacketCodec implements Error packet serialization
type ErrorPacketCodec struct{}

// Serialize encodes an ErrorPacket into binary format:
// [PacketTypeID(1B)][RPCID(8B)][MsgLen(4B)][Msg]
func (c *ErrorPacketCodec) Serialize(packet any) ([]byte, error) {
	p, ok := packet.(*ErrorPacket)
	if !ok {
		return nil, errors.New("invalid packet type for Error codec")
	}

	msgBytes := []byte(p.ErrorMsg)
	if len(msgBytes) > MaxQUICPayloadSize-13 { // 1+8+4 header = 13B
		return nil, errors.New("error message too long")
	}

	totalSize := 13 + len(msgBytes)
	buf := make([]byte, totalSize)

	// Write packet type ID (always PacketTypeError for error packets)
	buf[0] = byte(PacketTypeError)
	binary.LittleEndian.PutUint64(buf[1:9], p.RPCID)
	binary.LittleEndian.PutUint32(buf[9:13], uint32(len(msgBytes)))
	copy(buf[13:], msgBytes)

	return buf, nil
}

// Deserialize decodes binary data into an ErrorPacket
func (c *ErrorPacketCodec) Deserialize(data []byte) (any, error) {
	if len(data) < 13 {
		return nil, errors.New("data too short for ErrorPacket header")
	}

	pkt := &ErrorPacket{}
	// Skip packet type ID (first byte) - we know it's an error packet
	pkt.RPCID = binary.LittleEndian.Uint64(data[1:9])
	msgLen := binary.LittleEndian.Uint32(data[9:13])

	if len(data) < 13+int(msgLen) {
		return nil, errors.New("data too short for declared error message length")
	}

	pkt.ErrorMsg = string(data[13 : 13+msgLen])
	return pkt, nil
}
