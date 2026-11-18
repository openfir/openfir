package transport

import (
	"math"
	"sync"
	"time"
)

type KalmanOWDTracker struct {
	mu              sync.Mutex
	initialized     bool
	lastSendNano    int64
	lastRecvNano    int64
	minOneWayOffset int64
	hatGradMicros   float64
	errCovP         float64
	processNoiseQ   float64
	measureNoiseR   float64
	standingQueueUs int64
}

func NewKalmanOWDTracker() *KalmanOWDTracker {
	return &KalmanOWDTracker{
		minOneWayOffset: math.MaxInt64,
		errCovP:         100.0,
		processNoiseQ:   8.0,
		measureNoiseR:   220.0,
	}
}

func (k *KalmanOWDTracker) Observe(sendNano, recvNano int64) {
	if sendNano <= 0 || recvNano <= 0 {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()

	oneWay := recvNano - sendNano
	if oneWay < k.minOneWayOffset {
		k.minOneWayOffset = oneWay
	} else {
		k.minOneWayOffset += (oneWay - k.minOneWayOffset) / 100000
	}
	k.standingQueueUs = (oneWay - k.minOneWayOffset) / 1000

	if !k.initialized {
		k.initialized = true
		k.lastSendNano = sendNano
		k.lastRecvNano = recvNano
		return
	}

	if sendNano > k.lastSendNano {
		deltaSend := sendNano - k.lastSendNano
		deltaRecv := recvNano - k.lastRecvNano
		measuredGradUs := float64(deltaRecv-deltaSend) / 1000.0

		if measuredGradUs > -50000 && measuredGradUs < 50000 {
			pPred := k.errCovP + k.processNoiseQ
			kalmanGain := pPred / (pPred + k.measureNoiseR)
			k.hatGradMicros = k.hatGradMicros + kalmanGain*(measuredGradUs-k.hatGradMicros)
			k.errCovP = (1.0 - kalmanGain) * pPred
		}
		k.lastSendNano = sendNano
		k.lastRecvNano = recvNano
	}
}

func (k *KalmanOWDTracker) Snapshot() (gradMicros int64, queueMicros int64) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return int64(k.hatGradMicros), k.standingQueueUs
}

type MicroPacer struct {
	mu           sync.Mutex
	rateBps      float64
	minRateBps   float64
	maxRateBps   float64
	tokens       float64
	lastRefill   time.Time
	maxBurstSize float64
}

func NewMicroPacer(initialMBps, minMBps, maxMBps float64) *MicroPacer {
	initBps := initialMBps * 1024 * 1024
	return &MicroPacer{
		rateBps:      initBps,
		minRateBps:   minMBps * 1024 * 1024,
		maxRateBps:   maxMBps * 1024 * 1024,
		tokens:       64 * 1024,
		lastRefill:   time.Now(),
		maxBurstSize: 64 * 1024,
	}
}

func (p *MicroPacer) Wait(bytesToSend int) {
	p.mu.Lock()
	now := time.Now()
	elapsed := now.Sub(p.lastRefill).Seconds()
	p.lastRefill = now

	p.tokens += elapsed * p.rateBps
	if p.tokens > p.maxBurstSize {
		p.tokens = p.maxBurstSize
	}
	p.tokens -= float64(bytesToSend)

	var sleepDur time.Duration
	if p.tokens < 0 {
		waitSec := (-p.tokens) / p.rateBps
		sleepDur = time.Duration(waitSec * float64(time.Second))
	}
	p.mu.Unlock()

	if sleepDur > 400*time.Microsecond {
		time.Sleep(sleepDur)
	}
}

func (p *MicroPacer) UpdateFromKalman(gradMicros, standingQueueUs int64) {
	p.mu.Lock()
	defer p.mu.Unlock()

	const targetQueueUs = 4000

	if gradMicros < 40 && standingQueueUs < targetQueueUs {
		p.rateBps = p.rateBps*1.06 + 512*1024
	} else if gradMicros > 180 || standingQueueUs > targetQueueUs*2 {
		backoff := float64(gradMicros) / 4000.0
		if backoff < 0.02 {
			backoff = 0.02
		}
		if backoff > 0.15 {
			backoff = 0.15
		}
		p.rateBps = p.rateBps * (1.0 - backoff)
	}

	if p.rateBps < p.minRateBps {
		p.rateBps = p.minRateBps
	}
	if p.rateBps > p.maxRateBps {
		p.rateBps = p.maxRateBps
	}
}

func (p *MicroPacer) CurrentMBps() float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.rateBps / (1024 * 1024)
}
