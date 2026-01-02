package neko

const (
	DefaultWindowSize       = 30
	DefaultMaxOffset        = 64
	DefaultReplayCapacity   = 8192
	DefaultReplayWindows    = 4
	DefaultHandshakeSpan    = 1
	NetworkNonceLen         = 24
	FullTagLen              = 16
	FrameMetaLen            = 10
	PrebufferLen            = 4096
	HandshakeWaitMs         = 2000
	HandshakePeekIntervalMs = 100
	HandshakeMinPeek        = 64
	DefaultFallback         = "127.0.0.1:80"
	MaxSessionFrames        = 1 << 30
	ModeTCP                 = 0x00
	ModeUDP                 = 0x01
	SessionSaltLen          = 32
	DefaultMaxFrameLen      = 1400
)
