package neko

import (
	crand "crypto/rand"
	"math/big"
)

func fillBytes(buf []byte) error {
	_, err := crand.Read(buf)
	return err
}

func randIntn(n int) int {
	if n <= 0 {
		return 0
	}
	max := big.NewInt(int64(n))
	v, err := crand.Int(crand.Reader, max)
	if err != nil {
		return 0
	}
	return int(v.Int64())
}

func randRange(min, max int) int {
	if max <= min {
		return min
	}
	return min + randIntn(max-min+1)
}

func randChance(prob float64) bool {
	if prob <= 0 {
		return false
	}
	if prob >= 1 {
		return true
	}
	const scale = 10000
	threshold := int(prob * scale)
	if threshold <= 0 {
		return false
	}
	return randIntn(scale) < threshold
}
