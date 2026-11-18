package orch

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/csy20/agt/internal/store"
)

func TestRunLoopLimitScalesWithMaxSteps(t *testing.T) {
	if got := runLoopLimit(0); got != 64 {
		t.Fatalf("runLoopLimit(0) = %d, want 64", got)
	}
	if got := runLoopLimit(16); got < 64 {
		t.Fatalf("runLoopLimit(16) = %d, want >= 64", got)
	}
	if got := runLoopLimit(40); got != 40*4+16 {
		t.Fatalf("runLoopLimit(40) = %d, want %d", got, 40*4+16)
	}
}

func TestStepContextCancelsImmediatelyPastDeadline(t *testing.T) {
	past := store.Run{Deadline: time.Now().Add(-2 * time.Second)}
	sctx, cancel := stepContext(context.Background(), past)
	defer cancel()
	select {
	case <-sctx.Done():
	case <-time.After(100 * time.Millisecond):
		t.Fatal("stepContext with past deadline did not cancel immediately")
	}
	if !errors.Is(sctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("err = %v, want DeadlineExceeded", sctx.Err())
	}

	none, cancelNone := stepContext(context.Background(), store.Run{})
	defer cancelNone()
	if none.Err() != nil {
		t.Fatalf("zero deadline unexpectedly cancelled: %v", none.Err())
	}
}
