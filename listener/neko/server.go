package neko

import (
	"errors"
	"net"
	"strings"

	"github.com/metacubex/mihomo/adapter/inbound"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/transport/neko"
)

type Listener struct {
	listener     net.Listener
	addr         string
	closed       bool
	handler      *sing.ListenerHandler
	serverConfig neko.ServerConfig
	transportCfg neko.TransportConfig
	fallbackCfg  *neko.FallbackConfig
	fallbackDest string
	fallbackAddr socks5.Addr
}

// RawAddress implements C.Listener
func (l *Listener) RawAddress() string {
	return l.addr
}

// Address implements C.Listener
func (l *Listener) Address() string {
	if l.listener == nil {
		return ""
	}
	return l.listener.Addr().String()
}

// Close implements C.Listener
func (l *Listener) Close() error {
	l.closed = true
	if l.listener != nil {
		return l.listener.Close()
	}
	return nil
}

func (l *Listener) handleConn(conn net.Conn, tunnel C.Tunnel, additions ...inbound.Addition) {
	neko.ApplyTransport(conn, l.transportCfg)
	remoteHost, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	if l.fallbackCfg != nil && len(l.fallbackCfg.Whitelist) > 0 {
		allowed := false
		for _, ip := range l.fallbackCfg.Whitelist {
			if ip == remoteHost {
				allowed = true
				break
			}
		}
		if !allowed {
			neko.SilentFallback(conn, l.fallbackCfg)
			return
		}
	}

	session, payload, _, mode, err := neko.ServerHandshake(conn, l.serverConfig)
	if err != nil {
		response := neko.PickProbeResponse()
		switch response {
		case "blackhole":
			neko.SlowBlackholePlain(conn)
		case "fallback":
			neko.SilentFallback(conn, l.fallbackCfg)
		default:
			neko.CloseConn(conn)
		}
		return
	}

	if mode == neko.ModeUDP {
		l.handleUDPSession(session, tunnel, additions...)
		return
	}

	targetAddr := socks5.SplitAddr(payload)
	targetLen := 0
	if targetAddr != nil {
		targetLen = len(targetAddr)
	}
	if targetAddr == nil {
		if l.fallbackAddr == nil {
			_ = conn.Close()
			return
		}
		targetAddr = l.fallbackAddr
	}
	targetStr := targetAddr.String()
	earlyData := []byte(nil)
	if targetStr == l.fallbackDest && len(payload) > 0 {
		if targetLen > 0 && targetLen <= len(payload) {
			earlyData = payload[:targetLen]
		} else {
			earlyData = payload
		}
	}

	replayHandler := func(action neko.ReplayAction) {
		switch action {
		case neko.ReplayBlackhole:
			neko.SlowBlackhole(session)
		case neko.ReplayFallback:
			neko.SilentFallbackSplit(session.Conn(), session.WriterLock(), l.fallbackCfg)
		default:
			_ = session.Conn().Close()
		}
	}
	connWrapper := neko.NewConn(session, earlyData, replayHandler)
	l.handler.HandleSocket(targetAddr, connWrapper, additions...)
}

func (l *Listener) handleUDPSession(session *neko.Session, tunnel C.Tunnel, additions ...inbound.Addition) {
	remoteAddr := session.Conn().RemoteAddr()
	for {
		payload, action, err := session.ReadPacket()
		if action != neko.ReplayNone || err != nil {
			_ = session.Conn().Close()
			return
		}
		addr, data, err := socks5.DecodeUDPPacket(payload)
		if err != nil {
			continue
		}
		target := addr
		if target == nil {
			continue
		}
		packet := &udpPacket{
			payload: data,
			session: session,
			target:  target,
			rAddr:   remoteAddr,
		}
		tunnel.HandleUDPPacket(inbound.NewPacket(target, packet, C.NEKO, additions...))
	}
}

type udpPacket struct {
	payload []byte
	session *neko.Session
	target  socks5.Addr
	rAddr   net.Addr
}

func (p *udpPacket) Data() []byte {
	return p.payload
}

func (p *udpPacket) WriteBack(b []byte, addr net.Addr) (int, error) {
	socksAddr := p.target
	if addr != nil {
		if parsed := socks5.ParseAddrToSocksAddr(addr); parsed != nil {
			socksAddr = parsed
		}
	}
	packet, err := socks5.EncodeUDPPacket(socksAddr, b)
	if err != nil {
		return 0, err
	}
	if err := p.session.WritePacket(packet); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (p *udpPacket) Drop() {
	p.payload = nil
}

func (p *udpPacket) LocalAddr() net.Addr {
	return p.rAddr
}

func New(config LC.NEKOServer, tunnel C.Tunnel, additions ...inbound.Addition) (*Listener, error) {
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-NEKO"),
			inbound.WithSpecialRules(""),
		}
	}

	handler, err := sing.NewListenerHandler(sing.ListenerConfig{
		Tunnel:    tunnel,
		Type:      C.NEKO,
		Additions: additions,
		MuxOption: config.MuxOption,
	})
	if err != nil {
		return nil, err
	}

	l, err := inbound.Listen("tcp", config.Listen)
	if err != nil {
		return nil, err
	}

	pskBytes, err := neko.ParsePSK(config.PSK)
	if err != nil {
		_ = l.Close()
		return nil, err
	}
	if strings.TrimSpace(config.Cipher) == "" {
		_ = l.Close()
		return nil, errors.New("cipher is required")
	}

	jitterRange := [2]int{}
	if len(config.Shaping.JitterRange) >= 2 {
		jitterRange[0] = config.Shaping.JitterRange[0]
		jitterRange[1] = config.Shaping.JitterRange[1]
	} else if len(config.Shaping.JitterRange) == 1 {
		jitterRange[0] = config.Shaping.JitterRange[0]
		jitterRange[1] = config.Shaping.JitterRange[0]
	}
	shapingCfg := neko.ShapingConfig{
		Enabled:     config.Shaping.Enabled,
		JitterRange: jitterRange,
		MaxFrameLen: config.Shaping.MaxFrameLen,
	}

	fallbackDest := neko.DefaultFallback
	var fallbackCfg *neko.FallbackConfig
	if config.Fallback != nil {
		if config.Fallback.Dest != "" {
			fallbackDest = config.Fallback.Dest
		}
		fallbackCfg = &neko.FallbackConfig{
			Dest:      fallbackDest,
			Whitelist: config.Fallback.Whitelist,
		}
	}
	fallbackAddr := socks5.ParseAddr(fallbackDest)
	if fallbackAddr == nil {
		_ = l.Close()
		return nil, errors.New("invalid fallback dest")
	}

	replayFilter := neko.NewReplayFilter(config.ReplayCapacity, config.ReplayWindows)
	serverConfig := neko.ServerConfig{
		PSK:                    pskBytes,
		Cipher:                 strings.ToLower(config.Cipher),
		Shaping:                shapingCfg,
		WindowSize:             config.WindowSize,
		MaxOffset:              config.MaxOffset,
		HandshakeCandidateSpan: config.HandshakeCandidateSpan,
		ReplayCapacity:         config.ReplayCapacity,
		ReplayWindows:          config.ReplayWindows,
		ReplayFilter:           replayFilter,
	}

	tcpNoDelay := true
	if config.Transport.TCPNoDelay != nil {
		tcpNoDelay = *config.Transport.TCPNoDelay
	}
	transportCfg := neko.TransportConfig{
		TCPNoDelay:   tcpNoDelay,
		KeepAliveSec: config.Transport.KeepAliveSec,
	}

	sl := &Listener{
		listener:     l,
		addr:         config.Listen,
		handler:      handler,
		serverConfig: serverConfig,
		transportCfg: transportCfg,
		fallbackCfg:  fallbackCfg,
		fallbackDest: fallbackDest,
		fallbackAddr: fallbackAddr,
	}

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				if sl.closed {
					break
				}
				continue
			}
			go sl.handleConn(c, tunnel, additions...)
		}
	}()

	return sl, nil
}
