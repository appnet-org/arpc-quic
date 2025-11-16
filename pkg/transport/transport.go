package transport

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/appnet-org/arpc-quic/pkg/packet"
	"github.com/appnet-org/arpc-quic/pkg/transport/balancer"
	"github.com/appnet-org/arpc/pkg/logging"
	"github.com/quic-go/quic-go"
	"go.uber.org/zap"
)

// GenerateRPCID creates a unique RPC ID
func GenerateRPCID() uint64 {
	return uint64(time.Now().UnixNano())
}

type QUICTransport struct {
	listener    *quic.Listener
	conn        quic.Connection
	connMutex   sync.Mutex
	reassembler *DataReassembler
	resolver    *balancer.Resolver
	isServer    bool
}

func NewQUICTransport(address string) (*QUICTransport, error) {
	return NewQUICTransportWithBalancer(address, balancer.DefaultResolver())
}

// NewQUICTransportWithBalancer creates a new QUIC transport with a custom balancer
func NewQUICTransportWithBalancer(address string, resolver *balancer.Resolver) (*QUICTransport, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}

	// Create QUIC listener
	tlsConfig, err := generateServerTLSConfig()
	if err != nil {
		return nil, err
	}
	listener, err := quic.Listen(udpConn, tlsConfig, &quic.Config{
		MaxIdleTimeout: 30 * time.Second,
	})
	if err != nil {
		return nil, err
	}

	transport := &QUICTransport{
		listener:    listener,
		conn:        nil,
		reassembler: NewDataReassembler(),
		resolver:    resolver,
		isServer:    true,
	}

	return transport, nil
}

// NewQUICClientTransport creates a QUIC transport for client use
func NewQUICClientTransport() (*QUICTransport, error) {
	transport := &QUICTransport{
		listener:    nil,
		conn:        nil,
		reassembler: NewDataReassembler(),
		resolver:    balancer.DefaultResolver(),
		isServer:    false,
	}

	return transport, nil
}

// NewQUICTransportForConnection creates a QUIC transport for a server connection
// This is used to create a transport instance for each client connection
func NewQUICTransportForConnection(conn quic.Connection, resolver *balancer.Resolver) *QUICTransport {
	return &QUICTransport{
		listener:    nil,
		conn:        conn,
		connMutex:   sync.Mutex{},
		reassembler: NewDataReassembler(),
		resolver:    resolver,
		isServer:    true,
	}
}

// ResolveQUICTarget resolves a QUIC address string that may be an IP, FQDN, or empty.
// If it's empty or ":port", it binds to 0.0.0.0:<port>. For FQDNs, it uses the configured balancer
// to select an IP from the resolved addresses.
func ResolveQUICTarget(addr string) (*net.UDPAddr, error) {
	// Use default resolver for backward compatibility
	return balancer.DefaultResolver().ResolveUDPTarget(addr)
}

// connect ensures we have a QUIC connection to the target address (client only)
func (t *QUICTransport) connect(addr string) error {
	t.connMutex.Lock()
	defer t.connMutex.Unlock()

	// If we already have a connection, check if it's still alive
	if t.conn != nil {
		// Check if connection context is done (connection closed)
		select {
		case <-t.conn.Context().Done():
			// Connection is dead, close it
			t.conn.CloseWithError(0, "connection check failed")
			t.conn = nil
		default:
			// Connection seems alive
			return nil
		}
	}

	// If we don't have a connection, create one
	udpAddr, err := t.resolver.ResolveUDPTarget(addr)
	if err != nil {
		return err
	}

	conn, err := quic.DialAddr(context.Background(), udpAddr.String(), generateClientTLSConfig(), &quic.Config{
		MaxIdleTimeout: 30 * time.Second,
	})
	if err != nil {
		return err
	}
	t.conn = conn

	return nil
}

func (t *QUICTransport) Send(addr string, rpcID uint64, data []byte, packetTypeID packet.PacketTypeID) error {
	// For client mode, ensure we have a connection
	// For server mode, connection is already established
	if !t.isServer {
		if err := t.connect(addr); err != nil {
			return err
		}
	}

	// Ensure we have a connection
	t.connMutex.Lock()
	conn := t.conn
	t.connMutex.Unlock()
	if conn == nil {
		return fmt.Errorf("no connection available")
	}

	// Extract destination IP and port from the connection's remote address
	var dstIP [4]byte
	var dstPort uint16
	remoteAddr := conn.RemoteAddr().(*net.UDPAddr)
	if ip4 := remoteAddr.IP.To4(); ip4 != nil {
		copy(dstIP[:], ip4)
		dstPort = uint16(remoteAddr.Port)
	}

	// Get source IP and port from local address
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	var srcIP [4]byte
	if ip4 := localAddr.IP.To4(); ip4 != nil {
		copy(srcIP[:], ip4)
	}
	srcPort := uint16(localAddr.Port)

	// Fragment the data into multiple packets if needed
	packets, err := t.reassembler.FragmentData(data, rpcID, packetTypeID, dstIP, dstPort, srcIP, srcPort)
	if err != nil {
		return err
	}

	// Open a stream for sending data
	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		return err
	}
	defer stream.Close()

	// Iterate through each fragment and send it via the QUIC stream
	for _, pkt := range packets {
		var packetData []byte

		// Serialize based on packet type
		switch p := pkt.(type) {
		case *packet.DataPacket:
			packetData, err = packet.SerializeDataPacket(p)
		case *packet.ErrorPacket:
			packetData, err = packet.SerializeErrorPacket(p)
		default:
			return fmt.Errorf("unknown packet type: %T", pkt)
		}

		if err != nil {
			return fmt.Errorf("failed to serialize packet: %w", err)
		}

		logging.Debug("Serialized packet", zap.Uint64("rpcID", rpcID))

		// Write packet length first (4 bytes) for framing
		packetLen := uint32(len(packetData))
		lenBuf := make([]byte, 4)
		binary.LittleEndian.PutUint32(lenBuf, packetLen)
		if _, err := stream.Write(lenBuf); err != nil {
			return err
		}

		_, err = stream.Write(packetData)
		logging.Debug("Sent packet", zap.Uint64("rpcID", rpcID))
		if err != nil {
			return err
		}
	}

	return nil
}

// Receive takes a buffer size as input, read data from the QUIC stream, and return
// the following information when receiving the complete data for an RPC message:
// * complete data for a message (if no message is complete, it will return nil)
// * original source address from connection (for responses)
// * RPC id
// * packet type
// * error
func (t *QUICTransport) Receive(bufferSize int) ([]byte, *net.UDPAddr, uint64, packet.PacketTypeID, error) {
	// For client, use the existing connection
	var conn quic.Connection
	if t.isServer {
		// Server should use AcceptConnection to get a connection
		// This method is for receiving on an already accepted connection
		if t.conn == nil {
			return nil, nil, 0, packet.PacketTypeUnknown, fmt.Errorf("no connection available for server receive")
		}
		conn = t.conn
	} else {
		// Client uses the established connection
		t.connMutex.Lock()
		conn = t.conn
		t.connMutex.Unlock()
		if conn == nil {
			return nil, nil, 0, packet.PacketTypeUnknown, fmt.Errorf("no connection established for client receive")
		}
	}

	// Accept a stream from the connection
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		return nil, nil, 0, packet.PacketTypeUnknown, err
	}
	defer stream.Close()

	// Read packet length first (4 bytes) for framing
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(stream, lenBuf); err != nil {
		return nil, nil, 0, packet.PacketTypeUnknown, err
	}

	packetLen := binary.LittleEndian.Uint32(lenBuf)
	if packetLen > uint32(bufferSize) {
		return nil, nil, 0, packet.PacketTypeUnknown, fmt.Errorf("packet length %d exceeds buffer size %d", packetLen, bufferSize)
	}

	// Read the actual packet data
	buffer := make([]byte, packetLen)
	if _, err := io.ReadFull(stream, buffer); err != nil {
		return nil, nil, 0, packet.PacketTypeUnknown, err
	}

	// Get the remote address
	addr := conn.RemoteAddr().(*net.UDPAddr)

	// Deserialize the received data
	pkt, packetTypeID, err := packet.DeserializePacket(buffer)
	if err != nil {
		return nil, nil, 0, packet.PacketTypeUnknown, err
	}

	// Handle different packet types based on their nature
	switch p := pkt.(type) {
	case *packet.DataPacket:
		return t.ReassembleDataPacket(p, addr, packetTypeID)
	case *packet.ErrorPacket:
		return []byte(p.ErrorMsg), addr, p.RPCID, packetTypeID, nil
	default:
		// Unknown packet type - return early with no data
		logging.Debug("Unknown packet type", zap.Uint8("packetTypeID", uint8(packetTypeID)))
		return nil, nil, 0, packetTypeID, nil
	}
}

// AcceptConnection accepts a new QUIC connection (server only)
func (t *QUICTransport) AcceptConnection() (quic.Connection, error) {
	if !t.isServer || t.listener == nil {
		return nil, fmt.Errorf("AcceptConnection can only be called on a server transport")
	}
	return t.listener.Accept(context.Background())
}

// ReassembleDataPacket processes data packets through the reassembly layer
func (t *QUICTransport) ReassembleDataPacket(pkt *packet.DataPacket, addr *net.UDPAddr, packetTypeID packet.PacketTypeID) ([]byte, *net.UDPAddr, uint64, packet.PacketTypeID, error) {
	// Process fragment through reassembly layer
	fullMessage, _, reassembledRPCID, isComplete := t.reassembler.ProcessFragment(pkt, addr)

	if isComplete {
		// For responses, return the original source address from packet headers (SrcIP:SrcPort)
		// This allows the server to send responses back to the original client
		originalSrcAddr := &net.UDPAddr{
			IP:   net.IP(pkt.SrcIP[:]),
			Port: int(pkt.SrcPort),
		}
		return fullMessage, originalSrcAddr, reassembledRPCID, packetTypeID, nil
	}

	// Still waiting for more fragments
	return nil, nil, 0, packetTypeID, nil
}

// SetConnection sets the QUIC connection for this transport (used by server after accepting)
func (t *QUICTransport) SetConnection(conn quic.Connection) {
	t.connMutex.Lock()
	defer t.connMutex.Unlock()
	t.conn = conn
}

func (t *QUICTransport) Close() error {
	t.connMutex.Lock()
	defer t.connMutex.Unlock()

	var err error
	if t.conn != nil {
		err = t.conn.CloseWithError(0, "transport closed")
		t.conn = nil
	}

	if t.listener != nil {
		listenerErr := t.listener.Close()
		if err == nil {
			err = listenerErr
		}
		t.listener = nil
	}

	return err
}

// GetConn returns the underlying QUIC connection for direct packet sending
func (t *QUICTransport) GetConn() quic.Connection {
	t.connMutex.Lock()
	defer t.connMutex.Unlock()
	return t.conn
}

// LocalAddr returns the local UDP address of the transport
func (t *QUICTransport) LocalAddr() *net.UDPAddr {
	if t.listener != nil {
		return t.listener.Addr().(*net.UDPAddr)
	}
	t.connMutex.Lock()
	defer t.connMutex.Unlock()
	if t.conn != nil {
		return t.conn.LocalAddr().(*net.UDPAddr)
	}
	return nil
}

// GetResolver returns the resolver for this transport
func (t *QUICTransport) GetResolver() *balancer.Resolver {
	return t.resolver
}

// generateClientTLSConfig generates a basic TLS config for QUIC
// In production, you should use proper certificates
func generateClientTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "localhost",
		NextProtos:         []string{"arpc-quic"},
	}
}

// generateServerTLSConfig generates a self-signed TLS certificate for QUIC
func generateServerTLSConfig() (*tls.Config, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"ARPC-QUIC"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"arpc-quic"},
	}, nil
}
