package neko

type ClientConfig struct {
	PSK        []byte
	Cipher     string
	Shaping    ShapingConfig
	WindowSize int
	MaxOffset  int
}

type ServerConfig struct {
	PSK                    []byte
	Cipher                 string
	Shaping                ShapingConfig
	WindowSize             int
	MaxOffset              int
	HandshakeCandidateSpan int
	ReplayCapacity         int
	ReplayWindows          int
	ReplayFilter           *ReplayFilter
}

type TransportConfig struct {
	TCPNoDelay   bool
	KeepAliveSec int
}

type FallbackConfig struct {
	Dest      string
	Whitelist []string
}
