package packet

import (
	"errors"
)

const MaxUDPPayloadSize = 1400   // Adjust based on MTU considerations (deprecated, kept for compatibility)
const MaxTCPPayloadSize = 65535  // TCP can handle larger payloads, but we use a reasonable default (deprecated, kept for compatibility)
const MaxQUICPayloadSize = 65535 // QUIC can handle larger payloads, similar to TCP

// PacketCodec is the base interface that all codecs must implement
type PacketCodec interface {
	// Serialize converts a packet to its binary representation
	Serialize(packet any) ([]byte, error)

	// Deserialize converts binary data back to a packet
	Deserialize(data []byte) (any, error)
}

// SerializeDataPacket serializes a DataPacket
func SerializeDataPacket(pkt *DataPacket) ([]byte, error) {
	return dataPacketCodec.Serialize(pkt)
}

// SerializeErrorPacket serializes an ErrorPacket
func SerializeErrorPacket(pkt *ErrorPacket) ([]byte, error) {
	return errorPacketCodec.Serialize(pkt)
}

// DeserializePacket deserializes a packet by reading its type from the first byte
// and returns the packet and its type
func DeserializePacket(data []byte) (any, PacketTypeID, error) {
	if len(data) < 1 {
		return nil, PacketTypeUnknown, errors.New("data too short to read packet type")
	}

	// Packet type (uint8) is the first byte of the data
	packetTypeID := PacketTypeID(data[0])

	var codec PacketCodec
	switch packetTypeID {
	case PacketTypeData:
		codec = dataPacketCodec
	case PacketTypeError, PacketTypeUnknown:
		codec = errorPacketCodec
	default:
		return nil, PacketTypeUnknown, errors.New("unknown packet type")
	}

	// Deserialize using the codec
	packet, err := codec.Deserialize(data)
	if err != nil {
		return nil, PacketTypeUnknown, err
	}

	return packet, packetTypeID, nil
}
