package outbound

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/transport/neko"
)

type NEKO struct {
	*Base
	option    *NEKOOption
	clientCfg neko.ClientConfig
}

type NEKOShapingOption struct {
	Enabled     bool     `proxy:"enabled,omitempty"`
	NoiseRatio  *float64 `proxy:"noise-ratio,omitempty"`
	Persona     *string  `proxy:"persona,omitempty"`
	JitterRange []int    `proxy:"jitter-range,omitempty"`
	MaxFrameLen int      `proxy:"max-frame-len,omitempty"`
}

type NEKOTransportOption struct {
	TCPNoDelay   *bool `proxy:"tcp-nodelay,omitempty"`
	KeepAliveSec int   `proxy:"keep-alive-secs,omitempty"`
}

type NEKOOption struct {
	BasicOption
	Name       string             `proxy:"name"`
	Server     string             `proxy:"server"`
	Port       int                `proxy:"port"`
	PSK        string             `proxy:"psk"`
	Cipher     string             `proxy:"cipher"`
	UDP        bool               `proxy:"udp,omitempty"`
	WindowSize int                `proxy:"window-size,omitempty"`
	MaxOffset  int                `proxy:"max-offset,omitempty"`
	Shaping    NEKOShapingOption   `proxy:"shaping,omitempty"`
	Transport  NEKOTransportOption `proxy:"transport,omitempty"`
}

// DialContext implements C.ProxyAdapter
func (s *NEKO) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	if metadata == nil || metadata.DstPort == 0 || !metadata.Valid() {
		return nil, fmt.Errorf("invalid metadata for neko outbound")
	}
	target := socks5.ParseAddr(metadata.RemoteAddress())
	if target == nil {
		return nil, fmt.Errorf("invalid target address")
	}

	conn, err := s.dialer.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", s.addr, err)
	}
	defer func() {
		safeConnClose(conn, err)
	}()

	if ctx.Done() != nil {
		done := N.SetupContextForConn(ctx, conn)
		defer done(&err)
	}

	transportCfg := buildNEKOTransportConfig(s.option.Transport)
	neko.ApplyTransport(conn, transportCfg)
	session, err := neko.ClientHandshake(conn, s.clientCfg, target, neko.ModeTCP)
	if err != nil {
		return nil, err
	}

	return NewConn(neko.NewConn(session, nil, nil), s), nil
}

// ListenPacketContext implements C.ProxyAdapter
func (s *NEKO) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if err := s.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	target := socks5.ParseAddr(metadata.RemoteAddress())
	if target == nil {
		return nil, fmt.Errorf("invalid target address")
	}

	conn, err := s.dialer.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", s.addr, err)
	}
	defer func() {
		safeConnClose(conn, err)
	}()

	if ctx.Done() != nil {
		done := N.SetupContextForConn(ctx, conn)
		defer done(&err)
	}

	transportCfg := buildNEKOTransportConfig(s.option.Transport)
	neko.ApplyTransport(conn, transportCfg)
	session, err := neko.ClientHandshake(conn, s.clientCfg, target, neko.ModeUDP)
	if err != nil {
		return nil, err
	}

	pc := neko.NewPacketConn(session)
	return newPacketConn(N.NewThreadSafePacketConn(pc), s), nil
}

// ProxyInfo implements C.ProxyAdapter
func (s *NEKO) ProxyInfo() C.ProxyInfo {
	info := s.Base.ProxyInfo()
	info.DialerProxy = s.option.DialerProxy
	return info
}

func NewNEKO(option NEKOOption) (*NEKO, error) {
	if option.Server == "" {
		return nil, fmt.Errorf("server is required")
	}
	if option.Port <= 0 || option.Port > 65535 {
		return nil, fmt.Errorf("invalid port: %d", option.Port)
	}
	if option.PSK == "" {
		return nil, fmt.Errorf("psk is required")
	}
	pskBytes, err := neko.ParsePSK(option.PSK)
	if err != nil {
		return nil, err
	}
	cipher := strings.ToLower(option.Cipher)
	if cipher == "" {
		return nil, fmt.Errorf("cipher is required")
	}

	jitterRange := [2]int{}
	if len(option.Shaping.JitterRange) >= 2 {
		jitterRange[0] = option.Shaping.JitterRange[0]
		jitterRange[1] = option.Shaping.JitterRange[1]
	} else if len(option.Shaping.JitterRange) == 1 {
		jitterRange[0] = option.Shaping.JitterRange[0]
		jitterRange[1] = option.Shaping.JitterRange[0]
	}

	if option.Shaping.NoiseRatio != nil {
		log.Warnln("NEKO[%s] shaping noise-ratio is deprecated and ignored", option.Name)
	}
	if option.Shaping.Persona != nil {
		log.Warnln("NEKO[%s] shaping persona is deprecated and ignored", option.Name)
	}
	shapingCfg := neko.ShapingConfig{
		Enabled:     option.Shaping.Enabled,
		JitterRange: jitterRange,
		MaxFrameLen: option.Shaping.MaxFrameLen,
	}

	clientCfg := neko.ClientConfig{
		PSK:        pskBytes,
		Cipher:     cipher,
		Shaping:    shapingCfg,
		WindowSize: option.WindowSize,
		MaxOffset:  option.MaxOffset,
	}

	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	outbound := &NEKO{
		Base: &Base{
			name:   option.Name,
			addr:   addr,
			tp:     C.Neko,
			pdName: option.ProviderName,
			udp:    option.UDP,
			tfo:    option.TFO,
			mpTcp:  option.MPTCP,
			iface:  option.Interface,
			rmark:  option.RoutingMark,
			prefer: option.IPVersion,
		},
		option:    &option,
		clientCfg: clientCfg,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	return outbound, nil
}

func buildNEKOTransportConfig(option NEKOTransportOption) neko.TransportConfig {
	tcpNoDelay := true
	if option.TCPNoDelay != nil {
		tcpNoDelay = *option.TCPNoDelay
	}
	return neko.TransportConfig{
		TCPNoDelay:   tcpNoDelay,
		KeepAliveSec: option.KeepAliveSec,
	}
}
