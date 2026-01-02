package neko

import "time"

type ShapingConfig struct {
	Enabled     bool
	JitterRange [2]int
	MaxFrameLen int
}

type FrameShaper struct {
	enabled       bool
	maxPayloadLen int
	jitterMinMs   int
	jitterMaxMs   int
	jitterProb    float64
}

const defaultJitterProb = 0.04

func NewFrameShaper(cfg ShapingConfig, maxPayloadLen int) *FrameShaper {
	if maxPayloadLen <= 0 {
		maxPayloadLen = maxPayloadLenFromConfig(cfg)
	}
	jitterMin, jitterMax := normalizeJitterRange(cfg.JitterRange)
	return &FrameShaper{
		enabled:       cfg.Enabled,
		maxPayloadLen: maxPayloadLen,
		jitterMinMs:   jitterMin,
		jitterMaxMs:   jitterMax,
		jitterProb:    defaultJitterProb,
	}
}

func (s *FrameShaper) Split(n int) []int {
	if n <= 0 {
		return nil
	}
	maxLen := s.maxPayloadLen
	if maxLen <= 0 {
		maxLen = 1
	}
	parts := make([]int, 0, (n+maxLen-1)/maxLen)
	for n > 0 {
		size := maxLen
		if n < size {
			size = n
		}
		parts = append(parts, size)
		n -= size
	}
	return parts
}

func (s *FrameShaper) MaybeSleep() {
	if !s.enabled || s.jitterMaxMs <= 0 || s.jitterProb <= 0 {
		return
	}
	if randChance(s.jitterProb) {
		delay := randRange(s.jitterMinMs, s.jitterMaxMs)
		if delay > 0 {
			time.Sleep(time.Duration(delay) * time.Millisecond)
		}
	}
}

func maxPayloadLenFromConfig(cfg ShapingConfig) int {
	maxFrameLen := cfg.MaxFrameLen
	if maxFrameLen <= 0 {
		maxFrameLen = DefaultMaxFrameLen
	}
	if maxFrameLen < FrameMetaLen+1 {
		maxFrameLen = FrameMetaLen + 1
	}
	maxPayloadLen := maxFrameLen - FrameMetaLen
	if maxPayloadLen < 1 {
		maxPayloadLen = 1
	}
	return maxPayloadLen
}

func normalizeJitterRange(jitter [2]int) (int, int) {
	if jitter[0] > jitter[1] {
		jitter[0], jitter[1] = jitter[1], jitter[0]
	}
	if jitter[0] < 0 {
		jitter[0] = 0
	}
	if jitter[1] < 0 {
		jitter[1] = 0
	}
	return jitter[0], jitter[1]
}
