// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"math"
	"sync"
	"time"
)

const (
	DefaultInitMBps    = 4.0    // Safe 4 MiB/s (~33 Mbps) slow-start entry
	DefaultMinMBps     = 0.5    // 0.5 MiB/s floor (~4 Mbps)
	DefaultMaxMBps     = 1000.0 // 1000 MiB/s (~8 Gbps) ceiling
	TargetStandingUs   = 15000  // 15ms WAN-safe standing queue budget
	MinBurstBytes      = 32 * 1024
	MaxCARBurstBytes   = 256 * 1024 // CAR-safe burst cap
	DefaultSRTTMs      = 60.0
	MinRetxCooldownMs  = 25.0
)

// ============================================================================
// 1. Dimensionless Normalized Kalman One-Way Delay Gradient Tracker (1960 Kalman)
// ============================================================================

// NormalizedOWDTracker computes the dimensionless delay gradient:
//   g_k = (deltaRecv - deltaSend) / deltaSend
// which is strictly invariant across link rates from 1 Mbps to 40 Gbps.
type NormalizedOWDTracker struct {
	mu              sync.Mutex
	initialized     bool
	lastSendNano    int64
	lastRecvNano    int64
	curWinMin       int64
	prevWinMin      int64
	winStartNano    int64
	hatGradient     float64 // Dimensionless queue growth rate (0.0 = steady, +0.1 = queue growing at 10% of send rate)
	errCovP         float64
	processNoiseQ   float64
	measureNoiseR   float64
	standingQueueUs int64
}

func NewNormalizedOWDTracker() *NormalizedOWDTracker {
	return &NormalizedOWDTracker{
		curWinMin:     math.MaxInt64,
		prevWinMin:    math.MaxInt64,
		winStartNano:  time.Now().UnixNano(),
		errCovP:       0.05,
		processNoiseQ: 0.002,
		measureNoiseR: 0.04,
	}
}

func (k *NormalizedOWDTracker) Observe(sendNano, recvNano int64) {
	if sendNano <= 0 || recvNano <= 0 {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()

	oneWay := recvNano - sendNano

	// 2-bucket 10-second sliding minimum OWD baseline (immune to quartz clock drift & baseline creep)
	const bucketDurNano = int64(5 * time.Second)
	if recvNano-k.winStartNano >= bucketDurNano {
		k.prevWinMin = k.curWinMin
		k.curWinMin = oneWay
		k.winStartNano = recvNano
	} else if oneWay < k.curWinMin {
		k.curWinMin = oneWay
	}

	baseMin := k.curWinMin
	if k.prevWinMin < baseMin {
		baseMin = k.prevWinMin
	}
	if oneWay >= baseMin {
		k.standingQueueUs = (oneWay - baseMin) / 1000
	} else {
		k.standingQueueUs = 0
	}

	if !k.initialized {
		k.initialized = true
		k.lastSendNano = sendNano
		k.lastRecvNano = recvNano
		return
	}

	// Only evaluate gradient over >= 2ms intervals to smooth OS timer/GSO batching noise
	deltaSend := sendNano - k.lastSendNano
	if deltaSend >= int64(2*time.Millisecond) {
		deltaRecv := recvNano - k.lastRecvNano
		g := float64(deltaRecv-deltaSend) / float64(deltaSend)
		if g > -1.5 && g < 3.0 {
			pPred := k.errCovP + k.processNoiseQ
			gain := pPred / (pPred + k.measureNoiseR)
			k.hatGradient = k.hatGradient + gain*(g-k.hatGradient)
			k.errCovP = (1.0 - gain) * pPred
		}
		k.lastSendNano = sendNano
		k.lastRecvNano = recvNano
	}
}

func (k *NormalizedOWDTracker) Snapshot() (gradient float64, standingQueueUs int64) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.hatGradient, k.standingQueueUs
}

// ============================================================================
// 2. Delay-Gradient & Delivery-Rate Congestion Control (RFC 5681 + RFC 6298)
// ============================================================================

type Phase int

const (
	PhaseStartup Phase = iota // RFC 5681 style exponential slow start until delivery rate plateaus
	PhaseCruise               // Steady-state delay-gradient cruise & policer-safe tracking
)

type Controller struct {
	mu              sync.Mutex
	phase           Phase
	rateBps         float64
	minRateBps      float64
	maxRateBps      float64
	tokens          float64
	lastRefill      time.Time
	peakBwCur       float64
	peakBwPrev      float64
	bwWinStart      time.Time
	ewmaDeliveryBps float64
	plateauCount    int
	lastPeakBw      float64

	srttMs   float64
	rttVarMs float64
	minRTTMs float64
	rttInit  bool
	inflight int64
	ewmaLoss float64
}

func NewController(initMBps, minMBps, maxMBps float64) *Controller {
	if initMBps <= 0 {
		initMBps = DefaultInitMBps
	}
	if minMBps <= 0 {
		minMBps = DefaultMinMBps
	}
	if maxMBps < initMBps {
		maxMBps = initMBps
	}
	now := time.Now()
	return &Controller{
		phase:      PhaseStartup,
		rateBps:    initMBps * 1024 * 1024,
		minRateBps: minMBps * 1024 * 1024,
		maxRateBps: maxMBps * 1024 * 1024,
		tokens:     MinBurstBytes,
		lastRefill: now,
		bwWinStart: now,
		srttMs:     DefaultSRTTMs,
		rttVarMs:   DefaultSRTTMs / 2,
		minRTTMs:   DefaultSRTTMs,
	}
}

// ObserveRTT updates RFC 6298 smoothed RTT and minimum RTT.
func (c *Controller) ObserveRTT(sample time.Duration) {
	ms := float64(sample.Microseconds()) / 1000.0
	if ms < 0.2 || ms > 10000 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.rttInit {
		c.rttInit = true
		c.srttMs = ms
		c.rttVarMs = ms / 2
		c.minRTTMs = ms
		return
	}
	diff := math.Abs(c.srttMs - ms)
	c.rttVarMs = 0.75*c.rttVarMs + 0.25*diff
	c.srttMs = 0.875*c.srttMs + 0.125*ms
	if ms < c.minRTTMs {
		c.minRTTMs = ms
	}
}

// SRTT returns the current smoothed RTT.
func (c *Controller) SRTT() time.Duration {
	c.mu.Lock()
	ms := c.srttMs
	c.mu.Unlock()
	return time.Duration(ms * float64(time.Millisecond))
}

// RetransmitCooldown computes dynamic RTT-scaled retransmission cooldown = max(1.25*SRTT + RTTvar, 25ms),
// preventing retransmission storms on high-RTT transcontinental and satellite WANs.
func (c *Controller) RetransmitCooldown() time.Duration {
	c.mu.Lock()
	cdMs := 1.25*c.srttMs + c.rttVarMs
	c.mu.Unlock()
	if cdMs < MinRetxCooldownMs {
		cdMs = MinRetxCooldownMs
	}
	if cdMs > 2000 {
		cdMs = 2000
	}
	return time.Duration(cdMs * float64(time.Millisecond))
}

// InflightLimit returns the BDP-derived inflight ceiling = max(2.2 * PeakBw * SRTT, 512KB),
// preventing sender bufferbloat or flooding dead links.
func (c *Controller) InflightLimit() int64 {
	c.mu.Lock()
	bw := c.effectivePeakBwLocked()
	if bw < c.rateBps {
		bw = c.rateBps
	}
	srttSec := c.srttMs / 1000.0
	c.mu.Unlock()
	if srttSec < 0.010 {
		srttSec = 0.010
	}
	limit := int64(2.2 * bw * srttSec)
	if limit < 512*1024 {
		limit = 512 * 1024
	}
	if limit > 64*1024*1024 {
		limit = 64 * 1024 * 1024
	}
	return limit
}

func (c *Controller) OnPacketSent(wireBytes int) {
	c.mu.Lock()
	c.inflight += int64(wireBytes)
	c.mu.Unlock()
}

func (c *Controller) OnBytesAckedOrLost(wireBytes int) {
	c.mu.Lock()
	c.inflight -= int64(wireBytes)
	if c.inflight < 0 {
		c.inflight = 0
	}
	c.mu.Unlock()
}

func (c *Controller) Inflight() int64 {
	c.mu.Lock()
	v := c.inflight
	c.mu.Unlock()
	return v
}

func (c *Controller) effectivePeakBwLocked() float64 {
	bw := c.peakBwCur
	if c.peakBwPrev > bw {
		bw = c.peakBwPrev
	}
	return bw
}

// UpdateFromTelemetry updates pacing rate using strictly WIRE-BYTE delivery rate (never CAS/Zero inflated),
// dimensionless normalized OWD gradient, standing queue, and real UDP loss ratio.
func (c *Controller) UpdateFromTelemetry(wireDeliveryBps float64, normGradient float64, standingQueueUs int64, lossRatio float64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	if now.Sub(c.bwWinStart) >= 2*time.Second {
		c.peakBwPrev = c.peakBwCur
		c.peakBwCur = 0
		c.bwWinStart = now
	}
	if wireDeliveryBps > 0 {
		if c.ewmaDeliveryBps == 0 {
			c.ewmaDeliveryBps = wireDeliveryBps
		} else {
			c.ewmaDeliveryBps = c.ewmaDeliveryBps*0.60 + wireDeliveryBps*0.40
		}
	}
	if wireDeliveryBps > c.peakBwCur {
		c.peakBwCur = wireDeliveryBps
	}
	peakBw := c.effectivePeakBwLocked()

	if lossRatio >= 0 && lossRatio <= 1.0 {
		c.ewmaLoss = c.ewmaLoss*0.7 + lossRatio*0.3
	}

	// Startup -> Cruise exit when delivered bandwidth stops growing by >= 20% over 3 rounds
	if c.phase == PhaseStartup && peakBw > 0 {
		if peakBw >= c.lastPeakBw*1.20 {
			c.lastPeakBw = peakBw
			c.plateauCount = 0
		} else {
			c.plateauCount++
			if c.plateauCount >= 3 || standingQueueUs > TargetStandingUs*2 {
				c.phase = PhaseCruise
			}
		}
	}

	// Policer ceiling tracks recent real EWMA delivery rate so stale historical peaks cannot cause overshoot
	refBw := c.ewmaDeliveryBps
	if refBw <= 0 {
		refBw = peakBw
	}
	congestedQueue := normGradient > 0.08 || standingQueueUs > TargetStandingUs*2
	carPoliced := c.ewmaLoss > 0.04 && ((refBw > 0 && c.rateBps > refBw*1.12) || c.ewmaLoss > 0.10)

	switch {
	case congestedQueue:
		// Smooth proportional backoff based on dimensionless delay gradient
		backoff := normGradient * 0.5
		if backoff < 0.05 {
			backoff = 0.05
		}
		if backoff > 0.20 {
			backoff = 0.20
		}
		c.rateBps = c.rateBps * (1.0 - backoff)
		c.phase = PhaseCruise

	case carPoliced:
		// Zero-queue ISP CAR policer detected: converge smoothly to 1.12x real current delivered wire rate
		if refBw > 0 {
			target := refBw * 1.12
			c.rateBps = c.rateBps*0.65 + target*0.35
			if c.peakBwCur > refBw*1.25 {
				c.peakBwCur = refBw * 1.15
				c.peakBwPrev = refBw * 1.15
			}
		} else {
			c.rateBps = c.rateBps * 0.90
		}
		c.phase = PhaseCruise

	case c.phase == PhaseStartup:
		// Safe exponential slow-start ramp (1.45x per telemetry cycle)
		c.rateBps = c.rateBps * 1.45

	default:
		// Steady-state cruise additive/gentle multiplicative growth when queue is flat
		if normGradient < 0.03 && standingQueueUs < TargetStandingUs {
			if peakBw > 0 && c.rateBps < peakBw*1.25 {
				c.rateBps = c.rateBps*1.08 + 256*1024
			} else {
				c.rateBps = c.rateBps*1.03 + 128*1024
			}
		}
	}

	if c.rateBps < c.minRateBps {
		c.rateBps = c.minRateBps
	}
	if c.rateBps > c.maxRateBps {
		c.rateBps = c.maxRateBps
	}
}

// WaitPace enforces smooth CAR-safe token-bucket pacing (burst strictly capped at 2ms, max 256KB!).
func (c *Controller) WaitPace(bytesToSend int) {
	c.mu.Lock()
	now := time.Now()
	elapsed := now.Sub(c.lastRefill).Seconds()
	c.lastRefill = now

	maxBurst := c.rateBps * 0.002 // 2ms burst ceiling protects ISP CAR token buckets!
	if maxBurst < MinBurstBytes {
		maxBurst = MinBurstBytes
	}
	if maxBurst > MaxCARBurstBytes {
		maxBurst = MaxCARBurstBytes
	}

	c.tokens += elapsed * c.rateBps
	if c.tokens > maxBurst {
		c.tokens = maxBurst
	}
	c.tokens -= float64(bytesToSend)

	var sleepDur time.Duration
	if c.tokens < 0 {
		waitSec := (-c.tokens) / c.rateBps
		sleepDur = time.Duration(waitSec * float64(time.Second))
	}
	c.mu.Unlock()

	if sleepDur > 250*time.Microsecond {
		time.Sleep(sleepDur)
	}
}

func (c *Controller) CurrentMBps() float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rateBps / (1024 * 1024)
}

func (c *Controller) PeakBwMBps() float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.effectivePeakBwLocked() / (1024 * 1024)
}

func (c *Controller) Phase() Phase {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.phase
}
