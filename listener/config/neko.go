package config

import (
	"encoding/json"

	"github.com/metacubex/mihomo/listener/sing"
)

type NEKOShaping struct {
	Enabled     bool     `json:"enabled"`
	NoiseRatio  *float64 `json:"noise-ratio,omitempty"`
	Persona     string   `json:"persona,omitempty"`
	JitterRange []int    `json:"jitter-range,omitempty"`
	MaxFrameLen int      `json:"max-frame-len,omitempty"`
}

type NEKOTransport struct {
	TCPNoDelay   *bool `json:"tcp-nodelay,omitempty"`
	KeepAliveSec int   `json:"keep-alive-secs,omitempty"`
}

type NEKOFallback struct {
	Dest         string   `json:"dest,omitempty"`
	HTTPResponse string   `json:"http-response,omitempty"`
	Whitelist    []string `json:"whitelist,omitempty"`
}

// NEKOServer describes an NEKO inbound server configuration.
// It is internal to the listener layer and mainly used for logging and wiring.
type NEKOServer struct {
	Enable                 bool         `json:"enable"`
	Listen                 string       `json:"listen"`
	PSK                    string       `json:"psk"`
	Cipher                 string       `json:"cipher"`
	WindowSize             int          `json:"window-size,omitempty"`
	MaxOffset              int          `json:"max-offset,omitempty"`
	HandshakeCandidateSpan int          `json:"handshake-candidate-span,omitempty"`
	ReplayCapacity         int          `json:"replay-capacity,omitempty"`
	ReplayWindows          int          `json:"replay-windows,omitempty"`
	Shaping                NEKOShaping   `json:"shaping,omitempty"`
	Transport              NEKOTransport `json:"transport,omitempty"`
	Fallback               *NEKOFallback `json:"fallback,omitempty"`

	MuxOption sing.MuxOption `json:"mux-option,omitempty"`
}

func (s NEKOServer) String() string {
	b, _ := json.Marshal(s)
	return string(b)
}
