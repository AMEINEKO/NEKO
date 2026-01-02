package neko

import (
	"net"
	"sync"
	"time"
)

func ApplyTransport(conn net.Conn, cfg TransportConfig) {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(cfg.TCPNoDelay)
	}
}

func PickProbeResponse() string {
	roll := randIntn(100)
	if roll < 50 {
		return "blackhole"
	}
	if roll < 90 {
		return "fallback"
	}
	return "close"
}

func SlowBlackholePlain(conn net.Conn) {
	silentBlackholeConn(conn, 20*time.Second)
}

func CloseConn(conn net.Conn) {
	_ = conn.Close()
}

func SilentFallback(conn net.Conn, fallback *FallbackConfig) {
	_ = fallback
	buf := make([]byte, 256)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(time.Duration(randRange(3, 9)) * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if randIntn(100) < 10 {
					noise := make([]byte, randRange(1, 8))
					if fillBytes(noise) == nil {
						_, _ = conn.Write(noise)
					}
				}
				continue
			}
			return
		}
		if n == 0 {
			return
		}
	}
}

func SilentFallbackSplit(conn net.Conn, writeMu *sync.Mutex, fallback *FallbackConfig) {
	_ = fallback
	buf := make([]byte, 256)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(time.Duration(randRange(3, 9)) * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if randIntn(100) < 10 {
					noise := make([]byte, randRange(1, 8))
					if fillBytes(noise) == nil {
						writeMu.Lock()
						_, _ = conn.Write(noise)
						writeMu.Unlock()
					}
				}
				continue
			}
			return
		}
		if n == 0 {
			return
		}
	}
}

func SlowBlackhole(session *Session) {
	silentBlackholeConn(session.Conn(), 20*time.Second)
}

func silentBlackholeConn(conn net.Conn, duration time.Duration) {
	start := time.Now()
	buf := make([]byte, 1024)
	for time.Since(start) < duration {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err := conn.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			break
		}
	}
	_ = conn.Close()
}
