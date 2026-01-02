package inbound

import (
	"errors"
	"fmt"
	"strings"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/neko"
	"github.com/metacubex/mihomo/log"
)

type NEKOShapingOption struct {
	Enabled     bool     `inbound:"enabled,omitempty"`
	NoiseRatio  *float64 `inbound:"noise-ratio,omitempty"`
	Persona     *string  `inbound:"persona,omitempty"`
	JitterRange []int    `inbound:"jitter-range,omitempty"`
	MaxFrameLen int      `inbound:"max-frame-len,omitempty"`
}

type NEKOTransportOption struct {
	TCPNoDelay   *bool `inbound:"tcp-nodelay,omitempty"`
	KeepAliveSec int   `inbound:"keep-alive-secs,omitempty"`
}

type NEKOFallbackOption struct {
	Dest         string   `inbound:"dest,omitempty"`
	HTTPResponse string   `inbound:"http-response,omitempty"`
	Whitelist    []string `inbound:"whitelist,omitempty"`
}

type NEKOOption struct {
	BaseOption
	PSK                    string             `inbound:"psk"`
	Cipher                 string             `inbound:"cipher"`
	WindowSize             int                `inbound:"window-size,omitempty"`
	MaxOffset              int                `inbound:"max-offset,omitempty"`
	HandshakeCandidateSpan int                `inbound:"handshake-candidate-span,omitempty"`
	ReplayCapacity         int                `inbound:"replay-capacity,omitempty"`
	ReplayWindows          int                `inbound:"replay-windows,omitempty"`
	Shaping                NEKOShapingOption   `inbound:"shaping,omitempty"`
	Transport              NEKOTransportOption `inbound:"transport,omitempty"`
	Fallback               *NEKOFallbackOption `inbound:"fallback,omitempty"`

	MuxOption MuxOption `inbound:"mux-option,omitempty"`
}

func (o NEKOOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type NEKO struct {
	*Base
	config     *NEKOOption
	listeners  []*neko.Listener
	serverConf LC.NEKOServer
}

func NewNEKO(options *NEKOOption) (*NEKO, error) {
	if options.PSK == "" {
		return nil, fmt.Errorf("neko inbound requires psk")
	}
	if options.Cipher == "" {
		return nil, fmt.Errorf("neko inbound requires cipher")
	}
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}

	serverConf := LC.NEKOServer{
		Enable:                 true,
		Listen:                 base.RawAddress(),
		PSK:                    options.PSK,
		Cipher:                 strings.ToLower(options.Cipher),
		WindowSize:             options.WindowSize,
		MaxOffset:              options.MaxOffset,
		HandshakeCandidateSpan: options.HandshakeCandidateSpan,
		ReplayCapacity:         options.ReplayCapacity,
		ReplayWindows:          options.ReplayWindows,
		Shaping: LC.NEKOShaping{
			Enabled:     options.Shaping.Enabled,
			JitterRange: options.Shaping.JitterRange,
			MaxFrameLen: options.Shaping.MaxFrameLen,
		},
		Transport: LC.NEKOTransport{
			TCPNoDelay:   options.Transport.TCPNoDelay,
			KeepAliveSec: options.Transport.KeepAliveSec,
		},
	}
	if options.Shaping.NoiseRatio != nil {
		log.Warnln("NEKO inbound shaping noise-ratio is deprecated and ignored")
		serverConf.Shaping.NoiseRatio = options.Shaping.NoiseRatio
	}
	if options.Shaping.Persona != nil {
		log.Warnln("NEKO inbound shaping persona is deprecated and ignored")
		serverConf.Shaping.Persona = *options.Shaping.Persona
	}
	if options.Fallback != nil {
		serverConf.Fallback = &LC.NEKOFallback{
			Dest:         options.Fallback.Dest,
			HTTPResponse: options.Fallback.HTTPResponse,
			Whitelist:    options.Fallback.Whitelist,
		}
	}
	serverConf.MuxOption = options.MuxOption.Build()

	return &NEKO{
		Base:       base,
		config:     options,
		serverConf: serverConf,
	}, nil
}

// Config implements constant.InboundListener
func (s *NEKO) Config() C.InboundConfig {
	return s.config
}

// Address implements constant.InboundListener
func (s *NEKO) Address() string {
	var addrList []string
	for _, l := range s.listeners {
		addrList = append(addrList, l.Address())
	}
	return strings.Join(addrList, ",")
}

// Listen implements constant.InboundListener
func (s *NEKO) Listen(tunnel C.Tunnel) error {
	if s.serverConf.PSK == "" {
		return fmt.Errorf("neko inbound requires psk")
	}
	if s.serverConf.Cipher == "" {
		return fmt.Errorf("neko inbound requires cipher")
	}

	var errs []error
	for _, addr := range strings.Split(s.RawAddress(), ",") {
		conf := s.serverConf
		conf.Listen = addr
		l, err := neko.New(conf, tunnel, s.Additions()...)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		s.listeners = append(s.listeners, l)
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	log.Infoln("NEKO[%s] inbound listening at: %s", s.Name(), s.Address())
	return nil
}

// Close implements constant.InboundListener
func (s *NEKO) Close() error {
	var errs []error
	for _, l := range s.listeners {
		if err := l.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

var _ C.InboundListener = (*NEKO)(nil)
