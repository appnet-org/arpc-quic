package packet

// PacketTypeID is the type of packet
type PacketTypeID uint8

const (
	// PacketTypeUnknown represents an unknown packet type (used for errors)
	PacketTypeUnknown PacketTypeID = 0
	// PacketTypeData represents a data packet (used for requests and responses)
	PacketTypeData PacketTypeID = 1
	// PacketTypeError represents an error packet
	PacketTypeError PacketTypeID = 3
)
