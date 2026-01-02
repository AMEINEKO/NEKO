package neko

import (
	"encoding/binary"
	"sync"

	"github.com/metacubex/blake3"
)

type ReplayFilter struct {
	windows  []replayWindow
	capacity int
	mu       sync.Mutex
}

type replayWindow struct {
	id      int64
	entries map[uint64]struct{}
	ring    []uint64
	head    int
	count   int
}

func NewReplayFilter(capacity int, windows int) *ReplayFilter {
	if capacity <= 0 {
		capacity = DefaultReplayCapacity
	}
	if windows <= 0 {
		windows = DefaultReplayWindows
	}
	return &ReplayFilter{
		windows:  make([]replayWindow, windows),
		capacity: capacity,
	}
}

func (r *ReplayFilter) CheckAndSet(windowID int64, nonce []byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.windows) == 0 {
		return false
	}
	idx := int(windowID % int64(len(r.windows)))
	if idx < 0 {
		idx = -idx
	}
	window := &r.windows[idx]
	if window.id != windowID {
		window.id = windowID
		window.entries = make(map[uint64]struct{}, r.capacity)
		window.ring = make([]uint64, r.capacity)
		window.head = 0
		window.count = 0
	}
	key := hashReplayKey(windowID, nonce)
	if _, ok := window.entries[key]; ok {
		return true
	}
	if window.count >= r.capacity {
		evict := window.ring[window.head]
		delete(window.entries, evict)
	} else {
		window.count++
	}
	window.ring[window.head] = key
	window.head++
	if window.head >= r.capacity {
		window.head = 0
	}
	window.entries[key] = struct{}{}
	return false
}

func hashReplayKey(windowID int64, nonce []byte) uint64 {
	buf := make([]byte, 8+len(nonce))
	binary.LittleEndian.PutUint64(buf[:8], uint64(windowID))
	copy(buf[8:], nonce)
	digest := blake3.Sum256(buf)
	return binary.LittleEndian.Uint64(digest[0:8])
}
