package transport

import "sync"

const ReplayWindowWords = 128
const ReplayWindowBits = ReplayWindowWords * 64

// ReplayWindow implements an 8192-packet ring-buffer sliding anti-replay window.
type ReplayWindow struct {
	mu      sync.Mutex
	highest uint64
	ring    [ReplayWindowWords]uint64
	init    bool
}

func (rw *ReplayWindow) CheckAndAccept(seq uint64) bool {
	if seq == 0 {
		return false
	}
	rw.mu.Lock()
	defer rw.mu.Unlock()

	wordIdx := (seq >> 6) % ReplayWindowWords
	bitMask := uint64(1) << (seq & 63)

	if !rw.init {
		rw.init = true
		rw.highest = seq
		rw.ring[wordIdx] = bitMask
		return true
	}

	if seq > rw.highest {
		oldWord := rw.highest >> 6
		newWord := seq >> 6
		if newWord > oldWord {
			diffWords := newWord - oldWord
			if diffWords >= ReplayWindowWords {
				for i := 0; i < ReplayWindowWords; i++ {
					rw.ring[i] = 0
				}
			} else {
				for w := oldWord + 1; w <= newWord; w++ {
					rw.ring[w%ReplayWindowWords] = 0
				}
			}
		}
		rw.ring[wordIdx] |= bitMask
		rw.highest = seq
		return true
	}

	diff := rw.highest - seq
	if diff >= ReplayWindowBits-64 {
		return false
	}
	if (rw.ring[wordIdx] & bitMask) != 0 {
		return false
	}
	rw.ring[wordIdx] |= bitMask
	return true
}
