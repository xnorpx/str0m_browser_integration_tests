// Package pcap provides capturing wrappers for UDP connections.
package pcap

import (
	"net"

	transport "github.com/pion/transport/v4"
)

// UDPConn wraps a *net.UDPConn and records all sent/received UDP packets.
// It satisfies the transport.UDPConn interface.
type UDPConn struct {
	*net.UDPConn
	recorder  *Recorder
	localAddr net.UDPAddr
}

var _ transport.UDPConn = (*UDPConn)(nil)

// WrapUDPConn wraps an existing *net.UDPConn with packet recording.
func WrapUDPConn(conn *net.UDPConn, recorder *Recorder) *UDPConn {
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return &UDPConn{
		UDPConn:   conn,
		recorder:  recorder,
		localAddr: *localAddr,
	}
}

func (c *UDPConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = c.UDPConn.ReadFrom(p)
	if err == nil && n > 0 {
		if src, ok := addr.(*net.UDPAddr); ok {
			c.recorder.Record(*src, c.localAddr, p[:n])
		}
	}
	return
}

func (c *UDPConn) ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error) {
	n, addr, err = c.UDPConn.ReadFromUDP(b)
	if err == nil && n > 0 && addr != nil {
		c.recorder.Record(*addr, c.localAddr, b[:n])
	}
	return
}

func (c *UDPConn) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	n, oobn, flags, addr, err = c.UDPConn.ReadMsgUDP(b, oob)
	if err == nil && n > 0 && addr != nil {
		c.recorder.Record(*addr, c.localAddr, b[:n])
	}
	return
}

func (c *UDPConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	n, err = c.UDPConn.WriteTo(p, addr)
	if err == nil && n > 0 {
		if dst, ok := addr.(*net.UDPAddr); ok {
			c.recorder.Record(c.localAddr, *dst, p[:n])
		}
	}
	return
}

func (c *UDPConn) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	n, err := c.UDPConn.WriteToUDP(b, addr)
	if err == nil && n > 0 && addr != nil {
		c.recorder.Record(c.localAddr, *addr, b[:n])
	}
	return n, err
}

func (c *UDPConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	n, oobn, err = c.UDPConn.WriteMsgUDP(b, oob, addr)
	if err == nil && n > 0 && addr != nil {
		c.recorder.Record(c.localAddr, *addr, b[:n])
	}
	return
}

// Conn wraps a net.PacketConn and records all sent/received UDP packets.
// Used for UDPMux compatibility.
type Conn struct {
	net.PacketConn
	recorder  *Recorder
	localAddr net.UDPAddr
}

// WrapConn wraps an existing PacketConn with packet recording.
func WrapConn(conn net.PacketConn, recorder *Recorder) *Conn {
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return &Conn{
		PacketConn: conn,
		recorder:   recorder,
		localAddr:  *localAddr,
	}
}

func (c *Conn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = c.PacketConn.ReadFrom(p)
	if err == nil && n > 0 {
		if src, ok := addr.(*net.UDPAddr); ok {
			c.recorder.Record(*src, c.localAddr, p[:n])
		}
	}
	return
}

func (c *Conn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	n, err = c.PacketConn.WriteTo(p, addr)
	if err == nil && n > 0 {
		if dst, ok := addr.(*net.UDPAddr); ok {
			c.recorder.Record(c.localAddr, *dst, p[:n])
		}
	}
	return
}

// CaptureNet wraps a transport.Net and records all UDP packets
// from connections created via ListenUDP.
type CaptureNet struct {
	transport.Net
	recorder *Recorder
}

// NewCaptureNet creates a new CaptureNet wrapping the given transport.Net.
func NewCaptureNet(inner transport.Net, recorder *Recorder) *CaptureNet {
	return &CaptureNet{Net: inner, recorder: recorder}
}

func (n *CaptureNet) ListenUDP(network string, locAddr *net.UDPAddr) (transport.UDPConn, error) {
	conn, err := n.Net.ListenUDP(network, locAddr)
	if err != nil {
		return nil, err
	}
	// The inner transport returns *net.UDPConn, wrap it
	if raw, ok := conn.(*net.UDPConn); ok {
		return WrapUDPConn(raw, n.recorder), nil
	}
	// Can't wrap, return as-is
	return conn, nil
}

func (n *CaptureNet) ListenPacket(network string, address string) (net.PacketConn, error) {
	conn, err := n.Net.ListenPacket(network, address)
	if err != nil {
		return nil, err
	}
	return WrapConn(conn, n.recorder), nil
}

// Overrides to ensure the inner implementations are preserved
func (n *CaptureNet) Interfaces() ([]*transport.Interface, error) {
	return n.Net.Interfaces()
}

func (n *CaptureNet) InterfaceByIndex(index int) (*transport.Interface, error) {
	return n.Net.InterfaceByIndex(index)
}

func (n *CaptureNet) InterfaceByName(name string) (*transport.Interface, error) {
	return n.Net.InterfaceByName(name)
}
