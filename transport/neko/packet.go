package neko

import (
	"errors"
	"io"
	"net"
	"time"

	"github.com/metacubex/mihomo/transport/socks5"
)

type PacketConn struct {
	session *Session
}

func NewPacketConn(session *Session) *PacketConn {
	return &PacketConn{session: session}
}

func (pc *PacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		payload, action, err := pc.session.ReadPacket()
		if action != ReplayNone {
			return 0, nil, io.EOF
		}
		if err != nil {
			return 0, nil, err
		}
		addr, data, err := socks5.DecodeUDPPacket(payload)
		if err != nil {
			continue
		}
		udpAddr := addr.UDPAddr()
		if udpAddr == nil {
			return 0, nil, errors.New("parse udp addr error")
		}
		n := copy(p, data)
		return n, udpAddr, nil
	}
}

func (pc *PacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	packet, err := socks5.EncodeUDPPacket(socks5.ParseAddrToSocksAddr(addr), p)
	if err != nil {
		return 0, err
	}
	if err := pc.session.WritePacket(packet); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (pc *PacketConn) Close() error {
	return pc.session.conn.Close()
}

func (pc *PacketConn) LocalAddr() net.Addr {
	return pc.session.conn.LocalAddr()
}

func (pc *PacketConn) SetDeadline(t time.Time) error {
	return pc.session.conn.SetDeadline(t)
}

func (pc *PacketConn) SetReadDeadline(t time.Time) error {
	return pc.session.conn.SetReadDeadline(t)
}

func (pc *PacketConn) SetWriteDeadline(t time.Time) error {
	return pc.session.conn.SetWriteDeadline(t)
}
