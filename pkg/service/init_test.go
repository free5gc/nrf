package service

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestSuspendGraceElapsed pins the boundary: with a 20 second suspension
// deadline the suspend sweep stays quiet until 20 seconds of uptime.
func TestSuspendGraceElapsed(t *testing.T) {
	assert.False(t, suspendGraceElapsed(19*time.Second, 20*time.Second))
	assert.True(t, suspendGraceElapsed(20*time.Second, 20*time.Second))
}

// TestDropGraceElapsed pins the boundary: with a 20 second suspension deadline and a 10 second
// interval the drop sweep stays quiet through the first 30 seconds.
func TestDropGraceElapsed(t *testing.T) {
	assert.False(t, dropGraceElapsed(30*time.Second, 20*time.Second, 10*time.Second))
	assert.True(t, dropGraceElapsed(31*time.Second, 20*time.Second, 10*time.Second))
}

func TestSweepInterval(t *testing.T) {
	assert.Equal(t, 3*time.Second, sweepInterval(3))
	assert.Equal(t, maxSweepInterval, sweepInterval(10))
	assert.Equal(t, maxSweepInterval, sweepInterval(3600))
}
