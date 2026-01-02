package neko

import (
	"bytes"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type Session struct {
	conn           net.Conn
	reader         io.Reader
	cipher         *CipherInstance
	nonceMask      []byte
	nonceLen       int
	tagLen         int
	tagMask        []byte
	inboundShaper  *FrameShaper
	outboundShaper *FrameShaper
	inboundSeq     uint64
	outboundSeq    uint64
	replayFilter   *ReplayFilter
	windowSize     int
	readMu         sync.Mutex
	writeMu        sync.Mutex
}

func NewSession(conn net.Conn, reader io.Reader, cipher *CipherInstance, params *SessionParams, inboundShaper *FrameShaper, outboundShaper *FrameShaper, inboundSeq uint64, outboundSeq uint64, replayFilter *ReplayFilter, windowSize int) *Session {
	if reader == nil {
		reader = conn
	}
	return &Session{
		conn:           conn,
		reader:         reader,
		cipher:         cipher,
		nonceMask:      params.NonceMask,
		nonceLen:       params.NonceLen,
		tagLen:         params.TagLen,
		tagMask:        params.TagMask,
		inboundShaper:  inboundShaper,
		outboundShaper: outboundShaper,
		inboundSeq:     inboundSeq,
		outboundSeq:    outboundSeq,
		replayFilter:   replayFilter,
		windowSize:     windowSize,
	}
}

func (s *Session) ReadFrame() ([]byte, ReplayAction, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	return readFrame(s.reader, s.inboundShaper, s.cipher, s.nonceMask, s.nonceLen, s.tagLen, s.tagMask, s.replayFilter, &s.inboundSeq, s.windowSize)
}

func (s *Session) ReadPacket() ([]byte, ReplayAction, error) {
	for {
		payload, action, err := s.ReadFrame()
		if err != nil {
			return nil, action, err
		}
		if len(payload) == 0 {
			continue
		}
		return payload, action, nil
	}
}

func (s *Session) WriteFrames(data []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return sendFrames(s.conn, s.outboundShaper, s.cipher, s.nonceMask, s.nonceLen, s.tagLen, s.tagMask, &s.outboundSeq, data)
}

func (s *Session) WritePacket(data []byte) error {
	return s.WriteFrames(data)
}

func (s *Session) writeSingleFrame(payload []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	targetLen := FrameMetaLen + s.outboundShaper.maxPayloadLen
	if targetLen < FrameMetaLen+len(payload) {
		targetLen = FrameMetaLen + len(payload)
	}
	return writeFrame(s.conn, s.cipher, s.nonceMask, s.nonceLen, s.tagLen, s.tagMask, &s.outboundSeq, targetLen, payload)
}

func (s *Session) Conn() net.Conn {
	return s.conn
}

func (s *Session) WriterLock() *sync.Mutex {
	return &s.writeMu
}

type Conn struct {
	session       *Session
	preRead       *bytes.Reader
	readBuf       []byte
	replayOnce    sync.Once
	replayHandler func(ReplayAction)
	state         int32
}

const (
	connStateNormal = iota
	connStateReplay
)

func NewConn(session *Session, preRead []byte, replayHandler func(ReplayAction)) *Conn {
	var reader *bytes.Reader
	if len(preRead) > 0 {
		reader = bytes.NewReader(preRead)
	}
	return &Conn{
		session:       session,
		preRead:       reader,
		replayHandler: replayHandler,
		state:         connStateNormal,
	}
}

func (c *Conn) SetReplayHandler(handler func(ReplayAction)) {
	c.replayHandler = handler
}

func (c *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.preRead != nil && c.preRead.Len() > 0 {
		return c.preRead.Read(p)
	}
	if len(c.readBuf) == 0 {
		for {
			payload, action, err := c.session.ReadFrame()
			if action != ReplayNone {
				c.triggerReplay(action)
				return 0, io.EOF
			}
			if err != nil {
				return 0, err
			}
			if len(payload) == 0 {
				continue
			}
			c.readBuf = payload
			break
		}
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *Conn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if atomic.LoadInt32(&c.state) != connStateNormal {
		return 0, io.ErrClosedPipe
	}
	if err := c.session.WriteFrames(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *Conn) Close() error {
	atomic.StoreInt32(&c.state, connStateReplay)
	return c.session.conn.Close()
}

func (c *Conn) LocalAddr() net.Addr {
	return c.session.conn.LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.session.conn.RemoteAddr()
}

func (c *Conn) SetDeadline(t time.Time) error {
	return c.session.conn.SetDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.session.conn.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.session.conn.SetWriteDeadline(t)
}

func (c *Conn) triggerReplay(action ReplayAction) {
	c.replayOnce.Do(func() {
		atomic.StoreInt32(&c.state, connStateReplay)
		if c.replayHandler != nil {
			go c.replayHandler(action)
		}
	})
}

type prefixedReader struct {
	conn net.Conn
	buf  []byte
}

func newPrefixedReader(conn net.Conn, buf []byte) *prefixedReader {
	if len(buf) == 0 {
		return &prefixedReader{conn: conn}
	}
	copied := make([]byte, len(buf))
	copy(copied, buf)
	return &prefixedReader{conn: conn, buf: copied}
}

func (r *prefixedReader) Read(p []byte) (int, error) {
	if len(r.buf) > 0 {
		n := copy(p, r.buf)
		r.buf = r.buf[n:]
		return n, nil
	}
	return r.conn.Read(p)
}
