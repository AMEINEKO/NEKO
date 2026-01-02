package neko

import (
	"encoding/binary"
	"errors"
	"net"
	"time"
)

var ErrHandshakeFailed = errors.New("neko handshake failed")

func ClientHandshake(conn net.Conn, cfg ClientConfig, targetDesc []byte, mode byte) (*Session, error) {
	windowSize := cfg.WindowSize
	if windowSize <= 0 {
		windowSize = DefaultWindowSize
	}
	maxOffset := cfg.MaxOffset
	if maxOffset <= 0 {
		maxOffset = DefaultMaxOffset
	}
	if len(cfg.PSK) != 32 {
		return nil, errors.New("psk must be 32 bytes")
	}
	now := time.Now().Unix()
	params, err := deriveParams(cfg.PSK, now, cfg.Cipher, windowSize, maxOffset)
	if err != nil {
		return nil, err
	}
	handshakeCipher, err := NewCipher(cfg.Cipher, params.CipherKey)
	if err != nil {
		return nil, err
	}
	sessionSalt := make([]byte, SessionSaltLen)
	if err := fillBytes(sessionSalt); err != nil {
		return nil, err
	}
	payload := make([]byte, 0, SessionSaltLen+1+len(targetDesc))
	payload = append(payload, sessionSalt...)
	payload = append(payload, mode)
	payload = append(payload, targetDesc...)

	seq := uint64(0)
	_, err = writeHandshake(conn, handshakeCipher, params, &seq, payload)
	if err != nil {
		return nil, err
	}

	maxPayloadLen := maxPayloadLenFromConfig(cfg.Shaping)
	outboundShaper := NewFrameShaper(cfg.Shaping, maxPayloadLen)
	inboundShaper := NewFrameShaper(cfg.Shaping, maxPayloadLen)

	sessionParams, err := deriveSessionParams(cfg.PSK, sessionSalt, cfg.Cipher)
	if err != nil {
		return nil, err
	}
	sessionCipher, err := NewCipher(cfg.Cipher, sessionParams.CipherKey)
	if err != nil {
		return nil, err
	}
	return NewSession(conn, nil, sessionCipher, sessionParams, inboundShaper, outboundShaper, 0, seq, nil, windowSize), nil
}

type handshakeResult struct {
	sessionParams *SessionParams
	payload       []byte
	consumed      int
	mode          byte
}

func ServerHandshake(conn net.Conn, cfg ServerConfig) (*Session, []byte, []byte, byte, error) {
	windowSize := cfg.WindowSize
	if windowSize <= 0 {
		windowSize = DefaultWindowSize
	}
	maxOffset := cfg.MaxOffset
	if maxOffset <= 0 {
		maxOffset = DefaultMaxOffset
	}
	if len(cfg.PSK) != 32 {
		return nil, nil, nil, 0, errors.New("psk must be 32 bytes")
	}
	if cfg.ReplayFilter == nil {
		cfg.ReplayFilter = NewReplayFilter(cfg.ReplayCapacity, cfg.ReplayWindows)
	}

	span := cfg.HandshakeCandidateSpan
	if span <= 0 {
		span = DefaultHandshakeSpan
	}
	timeCandidates := make([]int64, 0, span*2+1)
	for i := -span; i <= span; i++ {
		timeCandidates = append(timeCandidates, int64(i))
	}
	now := time.Now().Unix()
	maxExpected := HandshakeMinPeek
	for _, delta := range timeCandidates {
		candidateTs := now + delta*int64(windowSize)
		params, err := deriveParams(cfg.PSK, candidateTs, cfg.Cipher, windowSize, maxOffset)
		if err != nil {
			continue
		}
		tagTailLen := FullTagLen - params.TagLen
		payloadLen := handshakePayloadLen(params.BaseSeed)
		targetLen := FrameMetaLen + payloadLen
		expectedTotal := params.Offset + tagTailLen + NetworkNonceLen + targetLen + params.TagLen
		if expectedTotal > maxExpected {
			maxExpected = expectedTotal
		}
	}
	requiredPeek := maxExpected
	if requiredPeek > PrebufferLen {
		requiredPeek = PrebufferLen
	}
	if requiredPeek < HandshakeMinPeek {
		requiredPeek = HandshakeMinPeek
	}

	preBuffer := make([]byte, 0, requiredPeek)
	start := time.Now()
	for len(preBuffer) < requiredPeek && time.Since(start) < time.Duration(HandshakeWaitMs)*time.Millisecond {
		_ = conn.SetReadDeadline(time.Now().Add(time.Duration(HandshakePeekIntervalMs) * time.Millisecond))
		tmp := make([]byte, requiredPeek-len(preBuffer))
		n, err := conn.Read(tmp)
		if n > 0 {
			preBuffer = append(preBuffer, tmp[:n]...)
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			break
		}
	}
	_ = conn.SetReadDeadline(time.Time{})
	if len(preBuffer) == 0 {
		return nil, nil, nil, 0, ErrHandshakeFailed
	}

	now = time.Now().Unix()
	for _, delta := range timeCandidates {
		candidateTs := now + delta*int64(windowSize)
		result, err := attemptHandshake(preBuffer, cfg, candidateTs, windowSize, maxOffset)
		if err != nil || result == nil {
			continue
		}
		leftover := preBuffer[result.consumed:]
		maxPayloadLen := maxPayloadLenFromConfig(cfg.Shaping)
		inboundShaper := NewFrameShaper(cfg.Shaping, maxPayloadLen)
		outboundShaper := NewFrameShaper(cfg.Shaping, maxPayloadLen)
		sessionCipher, err := NewCipher(cfg.Cipher, result.sessionParams.CipherKey)
		if err != nil {
			return nil, nil, nil, 0, err
		}
		reader := newPrefixedReader(conn, leftover)
		session := NewSession(conn, reader, sessionCipher, result.sessionParams, inboundShaper, outboundShaper, 1, 0, cfg.ReplayFilter, windowSize)
		return session, result.payload, leftover, result.mode, nil
	}

	return nil, nil, nil, 0, ErrHandshakeFailed
}

func attemptHandshake(preBuffer []byte, cfg ServerConfig, candidateTs int64, windowSize int, maxOffset int) (*handshakeResult, error) {
	params, err := deriveParams(cfg.PSK, candidateTs, cfg.Cipher, windowSize, maxOffset)
	if err != nil {
		return nil, err
	}
	tagTailLen := FullTagLen - params.TagLen
	payloadLen := handshakePayloadLen(params.BaseSeed)
	targetLen := FrameMetaLen + payloadLen
	expectedTotal := params.Offset + tagTailLen + NetworkNonceLen + targetLen + params.TagLen
	if len(preBuffer) < expectedTotal {
		return nil, nil
	}

	noncePos := params.Offset + tagTailLen
	encodedNonce := preBuffer[noncePos : noncePos+NetworkNonceLen]
	realNonce := decodeNonce(encodedNonce, params.NonceMask, params.NonceLen)
	handshakeCipher, err := NewCipher(cfg.Cipher, params.CipherKey)
	if err != nil {
		return nil, err
	}

	ciphertextStart := noncePos + NetworkNonceLen
	ciphertextEnd := ciphertextStart + targetLen
	tagPrefixStart := ciphertextEnd
	tagPrefixEnd := tagPrefixStart + params.TagLen
	ciphertext := preBuffer[ciphertextStart:ciphertextEnd]

	tag := make([]byte, FullTagLen)
	if params.TagLen > 0 {
		copy(tag[:params.TagLen], preBuffer[tagPrefixStart:tagPrefixEnd])
	}
	if tagTailLen > 0 {
		copy(tag[params.TagLen:], preBuffer[params.Offset:params.Offset+tagTailLen])
	}
	xorTag(tag, params.TagMask)

	ciphertextWithTag := make([]byte, 0, len(ciphertext)+FullTagLen)
	ciphertextWithTag = append(ciphertextWithTag, ciphertext...)
	ciphertextWithTag = append(ciphertextWithTag, tag...)
	plaintext, err := handshakeCipher.Decrypt(realNonce, ciphertextWithTag)
	if err != nil {
		return nil, nil
	}
	if len(plaintext) < FrameMetaLen {
		return nil, nil
	}
	seq := binary.LittleEndian.Uint64(plaintext[:8])
	if seq != 0 {
		return nil, nil
	}
	length := int(binary.LittleEndian.Uint16(plaintext[8:10]))
	if length > len(plaintext)-FrameMetaLen {
		return nil, nil
	}
	payload := plaintext[FrameMetaLen : FrameMetaLen+length]
	if len(payload) < SessionSaltLen+1 {
		return nil, nil
	}
	clientSalt := payload[:SessionSaltLen]
	mode := payload[SessionSaltLen]
	payload = payload[SessionSaltLen+1:]

	windowID := candidateTs / int64(windowSize)
	if cfg.ReplayFilter != nil && cfg.ReplayFilter.CheckAndSet(windowID, realNonce) {
		return nil, nil
	}

	sessionParams, err := deriveSessionParams(cfg.PSK, clientSalt, cfg.Cipher)
	if err != nil {
		return nil, err
	}

	return &handshakeResult{
		sessionParams: sessionParams,
		payload:       payload,
		consumed:      expectedTotal,
		mode:          mode,
	}, nil
}
