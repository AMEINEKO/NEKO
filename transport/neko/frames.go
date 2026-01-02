package neko

import (
	"encoding/binary"
	"errors"
	"io"
	"time"
)

type ReplayAction int

const (
	ReplayNone ReplayAction = iota
	ReplayBlackhole
	ReplayFallback
	ReplayClose
)

type HandshakeInfo struct {
	PayloadLen int
	Nonce      []byte
}

func writeHandshake(w io.Writer, cipher *CipherInstance, params *HandshakeParams, seq *uint64, payload []byte) (*HandshakeInfo, error) {
	payloadLen := handshakePayloadLen(params.BaseSeed)
	targetLen := FrameMetaLen + payloadLen
	if len(payload) > payloadLen {
		return nil, errors.New("handshake payload too large for frame")
	}

	paddedPayload := make([]byte, payloadLen)
	copy(paddedPayload, payload)
	if payloadLen > len(payload) {
		if err := fillBytes(paddedPayload[len(payload):]); err != nil {
			return nil, err
		}
	}

	frame := make([]byte, 0, targetLen)
	seqBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(seqBuf, *seq)
	frame = append(frame, seqBuf...)
	lenBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(lenBuf, uint16(payloadLen))
	frame = append(frame, lenBuf...)
	frame = append(frame, paddedPayload...)

	nonce := make([]byte, params.NonceLen)
	if err := fillBytes(nonce); err != nil {
		return nil, err
	}
	encodedNonce := make([]byte, NetworkNonceLen)
	if err := fillBytes(encodedNonce); err != nil {
		return nil, err
	}
	for i := 0; i < params.NonceLen; i++ {
		encodedNonce[i] = nonce[i] ^ params.NonceMask[i]
	}

	ciphertextWithTag, err := cipher.Encrypt(nonce, frame)
	if err != nil {
		return nil, err
	}
	if len(ciphertextWithTag) < FullTagLen {
		return nil, errors.New("ciphertext too short")
	}
	ciphertextLen := len(ciphertextWithTag) - FullTagLen
	tag := make([]byte, FullTagLen)
	copy(tag, ciphertextWithTag[ciphertextLen:])
	xorTag(tag, params.TagMask)

	tagTailLen := FullTagLen - params.TagLen
	tagPrefix := tag[:params.TagLen]
	tagTail := tag[params.TagLen:]

	noise := make([]byte, params.Offset+tagTailLen)
	if len(noise) > 0 {
		if err := fillBytes(noise); err != nil {
			return nil, err
		}
	}
	if tagTailLen > 0 {
		copy(noise[params.Offset:], tagTail)
	}

	if err := writeAll(w, noise); err != nil {
		return nil, err
	}
	if err := writeAll(w, encodedNonce); err != nil {
		return nil, err
	}
	if err := writeAll(w, ciphertextWithTag[:ciphertextLen]); err != nil {
		return nil, err
	}
	if params.TagLen > 0 {
		if err := writeAll(w, tagPrefix); err != nil {
			return nil, err
		}
	}

	*seq = (*seq + 1) & 0xFFFFFFFFFFFFFFFF
	return &HandshakeInfo{PayloadLen: payloadLen, Nonce: nonce}, nil
}

func sendFrames(w io.Writer, shaper *FrameShaper, cipher *CipherInstance, nonceMask []byte, nonceLen int, tagLen int, tagMask []byte, seq *uint64, data []byte) error {
	if shaper == nil {
		return errors.New("missing shaper")
	}
	segments := shaper.Split(len(data))
	cursor := 0
	for _, segLen := range segments {
		shaper.MaybeSleep()
		remaining := len(data) - cursor
		if remaining <= 0 {
			return nil
		}
		take := segLen
		if take > remaining {
			take = remaining
		}
		payload := data[cursor : cursor+take]
		targetLen := FrameMetaLen + shaper.maxPayloadLen
		if targetLen < FrameMetaLen+len(payload) {
			targetLen = FrameMetaLen + len(payload)
		}
		if err := writeFrame(w, cipher, nonceMask, nonceLen, tagLen, tagMask, seq, targetLen, payload); err != nil {
			return err
		}
		cursor += take
	}
	return nil
}

func writeFrame(w io.Writer, cipher *CipherInstance, nonceMask []byte, nonceLen int, tagLen int, tagMask []byte, seq *uint64, targetLen int, payload []byte) error {
	if *seq >= MaxSessionFrames {
		return errors.New("max session frames exceeded")
	}
	available := targetLen - FrameMetaLen
	if available < 0 {
		available = 0
	}
	if len(payload) > available {
		return errors.New("payload too large for frame")
	}

	frame := make([]byte, 0, targetLen)
	seqBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(seqBuf, *seq)
	frame = append(frame, seqBuf...)
	lenBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(lenBuf, uint16(len(payload)))
	frame = append(frame, lenBuf...)
	frame = append(frame, payload...)
	if targetLen > len(frame) {
		padLen := targetLen - len(frame)
		pad := make([]byte, padLen)
		if err := fillBytes(pad); err != nil {
			return err
		}
		frame = append(frame, pad...)
	}

	nonce := make([]byte, nonceLen)
	if err := fillBytes(nonce); err != nil {
		return err
	}
	encodedNonce := make([]byte, NetworkNonceLen)
	if err := fillBytes(encodedNonce); err != nil {
		return err
	}
	for i := 0; i < nonceLen; i++ {
		encodedNonce[i] = nonce[i] ^ nonceMask[i]
	}

	ciphertextWithTag, err := cipher.Encrypt(nonce, frame)
	if err != nil {
		return err
	}
	if len(ciphertextWithTag) < FullTagLen {
		return errors.New("ciphertext too short")
	}
	ciphertextLen := len(ciphertextWithTag) - FullTagLen
	tag := make([]byte, FullTagLen)
	copy(tag, ciphertextWithTag[ciphertextLen:])
	xorTag(tag, tagMask)
	tagTailLen := FullTagLen - tagLen
	tagPrefix := tag[:tagLen]
	tagTail := tag[tagLen:]

	if tagTailLen > 0 {
		if err := writeAll(w, tagTail); err != nil {
			return err
		}
	}
	if err := writeAll(w, encodedNonce); err != nil {
		return err
	}
	if err := writeAll(w, ciphertextWithTag[:ciphertextLen]); err != nil {
		return err
	}
	if tagLen > 0 {
		if err := writeAll(w, tagPrefix); err != nil {
			return err
		}
	}

	*seq = (*seq + 1) & 0xFFFFFFFFFFFFFFFF
	return nil
}

func readFrame(r io.Reader, shaper *FrameShaper, cipher *CipherInstance, nonceMask []byte, nonceLen int, tagLen int, tagMask []byte, replayFilter *ReplayFilter, expectedSeq *uint64, windowSize int) ([]byte, ReplayAction, error) {
	if shaper == nil {
		return nil, ReplayNone, errors.New("missing shaper")
	}
	targetLen := FrameMetaLen + shaper.maxPayloadLen
	tagTailLen := FullTagLen - tagLen
	var tagTail []byte
	if tagTailLen > 0 {
		var err error
		tagTail, err = readExact(r, tagTailLen)
		if err != nil {
			return nil, ReplayNone, err
		}
	}
	encodedNonce, err := readExact(r, NetworkNonceLen)
	if err != nil {
		return nil, ReplayNone, err
	}
	ciphertext, err := readExact(r, targetLen)
	if err != nil {
		return nil, ReplayNone, err
	}
	var tagPrefix []byte
	if tagLen > 0 {
		tagPrefix, err = readExact(r, tagLen)
		if err != nil {
			return nil, ReplayNone, err
		}
	}

	realNonce := decodeNonce(encodedNonce, nonceMask, nonceLen)
	if replayFilter != nil && windowSize > 0 {
		windowID := time.Now().Unix() / int64(windowSize)
		if replayFilter.CheckAndSet(windowID, realNonce) {
			roll := randIntn(100)
			switch {
			case roll < 34:
				return nil, ReplayBlackhole, errors.New("replay")
			case roll < 67:
				return nil, ReplayFallback, errors.New("replay")
			default:
				return nil, ReplayClose, errors.New("replay")
			}
		}
	}

	tag := make([]byte, FullTagLen)
	if tagLen > 0 {
		copy(tag[:tagLen], tagPrefix)
	}
	if tagTailLen > 0 {
		copy(tag[tagLen:], tagTail)
	}
	xorTag(tag, tagMask)
	ciphertextWithTag := make([]byte, 0, len(ciphertext)+FullTagLen)
	ciphertextWithTag = append(ciphertextWithTag, ciphertext...)
	ciphertextWithTag = append(ciphertextWithTag, tag...)
	plaintext, err := cipher.Decrypt(realNonce, ciphertextWithTag)
	if err != nil {
		return nil, ReplayNone, err
	}
	if len(plaintext) < FrameMetaLen {
		return nil, ReplayNone, io.EOF
	}
	seq := binary.LittleEndian.Uint64(plaintext[:8])
	if seq != *expectedSeq {
		return nil, ReplayNone, io.EOF
	}
	*expectedSeq = (*expectedSeq + 1) & 0xFFFFFFFFFFFFFFFF
	length := int(binary.LittleEndian.Uint16(plaintext[8:10]))
	if length > len(plaintext)-FrameMetaLen {
		return nil, ReplayNone, io.EOF
	}
	payload := plaintext[FrameMetaLen : FrameMetaLen+length]
	return payload, ReplayNone, nil
}

func readExact(r io.Reader, n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	return buf, err
}

func writeAll(w io.Writer, buf []byte) error {
	for len(buf) > 0 {
		n, err := w.Write(buf)
		if err != nil {
			return err
		}
		buf = buf[n:]
	}
	return nil
}
