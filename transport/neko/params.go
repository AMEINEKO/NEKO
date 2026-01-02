package neko

import (
	"encoding/binary"
	"errors"
	"strings"

	"github.com/metacubex/blake3"
)

type HandshakeParams struct {
	CipherKey []byte
	NonceMask []byte
	NonceLen  int
	Offset    int
	BaseSeed  []byte
	TagLen    int
	TagMask   []byte
}

type SessionParams struct {
	SessionKey []byte
	CipherKey  []byte
	NonceMask  []byte
	NonceLen   int
	TagLen     int
	TagMask    []byte
}

func deriveParams(psk []byte, timestamp int64, cipher string, windowSize int, maxOffset int) (*HandshakeParams, error) {
	windowID := timestamp / int64(windowSize)
	windowBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(windowBytes, uint64(windowID))
	baseSeed := blake3KeyedHash(psk, windowBytes)
	cipherKeyFull := blake3DeriveKey("neko-cipher-key", baseSeed, 32)
	nonceMaskFull := blake3DeriveKey("neko-nonce-mask", baseSeed, 32)
	tagMaskFull := blake3DeriveKey("neko-tag-mask", baseSeed, 32)
	offsetSeed := blake3DeriveKey("neko-offset-seed", baseSeed, 32)
	tagLen := 12 + int(baseSeed[0]%5)
	nonceLen, err := cipherNonceLen(cipher)
	if err != nil {
		return nil, err
	}
	keyLen, err := cipherKeyLen(cipher)
	if err != nil {
		return nil, err
	}
	offset := 0
	if maxOffset > 0 {
		offset = int(offsetSeed[0]) % maxOffset
	}
	return &HandshakeParams{
		CipherKey: cipherKeyFull[:keyLen],
		NonceMask: nonceMaskFull[:nonceLen],
		NonceLen:  nonceLen,
		Offset:    offset,
		BaseSeed:  baseSeed,
		TagLen:    tagLen,
		TagMask:   tagMaskFull[:FullTagLen],
	}, nil
}

func deriveSessionParams(psk []byte, sessionSalt []byte, cipher string) (*SessionParams, error) {
	seedInput := make([]byte, 0, len(psk)+len(sessionSalt))
	seedInput = append(seedInput, psk...)
	seedInput = append(seedInput, sessionSalt...)
	seed := blake3.Sum256(seedInput)
	sessionKey := seed[:]
	sessionBase := blake3DeriveKey("neko-session-base", seed[:], 32)
	cipherKeyFull := blake3DeriveKey("neko-session-cipher", sessionBase, 32)
	nonceMaskFull := blake3DeriveKey("neko-session-nonce-mask", sessionBase, 32)
	tagMaskFull := blake3DeriveKey("neko-session-tag-mask", sessionBase, 32)
	tagLen := 12 + int(sessionBase[0]%5)
	nonceLen, err := cipherNonceLen(cipher)
	if err != nil {
		return nil, err
	}
	keyLen, err := cipherKeyLen(cipher)
	if err != nil {
		return nil, err
	}
	return &SessionParams{
		SessionKey: sessionKey,
		CipherKey:  cipherKeyFull[:keyLen],
		NonceMask:  nonceMaskFull[:nonceLen],
		NonceLen:   nonceLen,
		TagLen:     tagLen,
		TagMask:    tagMaskFull[:FullTagLen],
	}, nil
}

func deriveSeed(base []byte, label string) []byte {
	return blake3DeriveKey(label, base, 32)
}

func deriveConnectionSeed(baseSeed []byte, nonce []byte) []byte {
	return blake3KeyedHash(baseSeed, nonce)
}

func handshakePayloadLen(baseSeed []byte) int {
	minLen := 320
	span := 321
	return minLen + int(baseSeed[0])%span
}

func decodeNonce(encoded []byte, mask []byte, nonceLen int) []byte {
	nonce := make([]byte, nonceLen)
	for i := 0; i < nonceLen; i++ {
		nonce[i] = encoded[i] ^ mask[i]
	}
	return nonce
}

func xorTag(tag []byte, mask []byte) {
	for i := 0; i < FullTagLen; i++ {
		tag[i] ^= mask[i]
	}
}

func cipherKeyLen(kind string) (int, error) {
	switch strings.ToLower(kind) {
	case "aes-128-gcm":
		return 16, nil
	case "aes-256-gcm":
		return 32, nil
	case "chacha20-poly1305", "xchacha20-poly1305":
		return 32, nil
	default:
		return 0, errors.New("unsupported cipher")
	}
}

func cipherNonceLen(kind string) (int, error) {
	switch strings.ToLower(kind) {
	case "xchacha20-poly1305":
		return 24, nil
	case "aes-128-gcm", "aes-256-gcm", "chacha20-poly1305":
		return 12, nil
	default:
		return 0, errors.New("unsupported cipher")
	}
}
