package neko

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/metacubex/blake3"
	"golang.org/x/crypto/chacha20poly1305"
)

type CipherInstance struct {
	aead cipher.AEAD
}

func NewCipher(kind string, key []byte) (*CipherInstance, error) {
	switch strings.ToLower(kind) {
	case "aes-128-gcm", "aes-256-gcm":
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		return &CipherInstance{aead: aead}, nil
	case "chacha20-poly1305":
		aead, err := chacha20poly1305.New(key)
		if err != nil {
			return nil, err
		}
		return &CipherInstance{aead: aead}, nil
	case "xchacha20-poly1305":
		aead, err := chacha20poly1305.NewX(key)
		if err != nil {
			return nil, err
		}
		return &CipherInstance{aead: aead}, nil
	default:
		return nil, errors.New("unsupported cipher")
	}
}

func (c *CipherInstance) Encrypt(nonce, plaintext []byte) ([]byte, error) {
	return c.aead.Seal(nil, nonce, plaintext, nil), nil
}

func (c *CipherInstance) Decrypt(nonce, ciphertext []byte) ([]byte, error) {
	return c.aead.Open(nil, nonce, ciphertext, nil)
}

func ParsePSK(psk string) ([]byte, error) {
	trimmed := strings.TrimSpace(psk)
	if trimmed == "" {
		return nil, errors.New("psk is empty")
	}
	if decoded, err := base64.StdEncoding.DecodeString(trimmed); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(trimmed); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	if decoded, err := hex.DecodeString(trimmed); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	return nil, errors.New("expected 32-byte PSK in base64 or hex")
}

func blake3KeyedHash(key, data []byte) []byte {
	h := blake3.New(32, key)
	_, _ = h.Write(data)
	return h.Sum(nil)
}

func blake3DeriveKey(context string, data []byte, outLen int) []byte {
	out := make([]byte, outLen)
	blake3.DeriveKey(out, context, data)
	return out
}
