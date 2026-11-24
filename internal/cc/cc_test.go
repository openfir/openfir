// SPDX-License-Identifier: Apache-2.0

package cc

import (
	"math"
	"testing"
	"time"
)

func TestNormalizedOWDGIsRateInvariant(t *testing.T) {
	// Same 10% queue buildup rate (deltaRecv = 1.10 * deltaSend) at BOTH 10 Mbps and 1 Gbps!
	trSlow := NewNormalizedOWDTracker()
	trFast := NewNormalizedOWDTracker()

	// 10 Mbps (~10ms spacing) vs 1 Gbps (~3ms spacing), both growing delay by 10% of send interval
	for i := int64(0); i < 40; i++ {
		trSlow.Observe(1_000_000_000+i*10_000_000, 1_000_000_000+i*11_000_000)
		trFast.Observe(1_000_000_000+i*3_000_000, 1_000_000_000+i*3_300_000)
	}
	gSlow, _ := trSlow.Snapshot()
	gFast, _ := trFast.Snapshot()
	if math.Abs(gSlow-0.10) > 0.02 || math.Abs(gFast-0.10) > 0.02 {
		t.Fatalf("Normalized OWDG not rate-invariant: gSlow=%.4f gFast=%.4f (want ~0.10)", gSlow, gFast)
	}
	t.Logf("PASS: Normalized OWDG rate-invariant (gSlow=%.4f, gFast=%.4f vs true 0.1000)", gSlow, gFast)
}

func TestRTTScaledCooldownPreventsTranscontinentalRetxStorm(t *testing.T) {
	c := NewController(4.0, 0.5, 1000.0)
	// Transcontinental 180ms RTT
	for i := 0; i < 10; i++ {
		c.ObserveRTT(180 * time.Millisecond)
	}
	cd := c.RetransmitCooldown()
	if cd < 220*time.Millisecond {
		t.Fatalf("180ms WAN cooldown too short (%v < 220ms)", cd)
	}
	// Satellite 600ms RTT
	cSat := NewController(4.0, 0.5, 1000.0)
	for i := 0; i < 10; i++ {
		cSat.ObserveRTT(600 * time.Millisecond)
	}
	cdSat := cSat.RetransmitCooldown()
	if cdSat < 740*time.Millisecond {
		t.Fatalf("600ms satellite cooldown too short (%v < 740ms)", cdSat)
	}
	t.Logf("PASS: Dynamic RTT-scaled cooldown: 180ms WAN -> %v | 600ms Satellite -> %v", cd.Round(time.Millisecond), cdSat.Round(time.Millisecond))
}

func TestSlowStartExitsOnPlateauAndRespectsCARPolicer(t *testing.T) {
	c := NewController(4.0, 0.5, 1000.0)
	if c.CurrentMBps() != 4.0 || c.Phase() != PhaseStartup {
		t.Fatalf("expected safe 4 MiB/s Slow Start, got %.1f phase=%d", c.CurrentMBps(), c.Phase())
	}
	// Ramp up smoothly during Startup
	for i := 0; i < 5; i++ {
		c.UpdateFromTelemetry(float64(8*(i+1))*1024*1024, 0.0, 1000, 0.0)
	}
	if c.CurrentMBps() <= 16.0 {
		t.Fatalf("Slow Start failed to ramp up: %.2f MiB/s", c.CurrentMBps())
	}
	// Simulate zero-queue CAR policer capping real delivery at 20 MiB/s with 15% loss
	for i := 0; i < 12; i++ {
		c.UpdateFromTelemetry(20*1024*1024, 0.0, 500, 0.15)
	}
	if c.Phase() != PhaseCruise {
		t.Fatal("expected exit from Startup to Cruise")
	}
	if c.CurrentMBps() > 30.0 {
		t.Fatalf("CAR policer defense failed to cap pacing near 1.12x delivery (22.4 MiB/s), got %.2f MiB/s", c.CurrentMBps())
	}
	t.Logf("PASS: Slow Start + CAR Policer converged smoothly to %.2f MiB/s (PeakBw=%.2f MiB/s)", c.CurrentMBps(), c.PeakBwMBps())
}
