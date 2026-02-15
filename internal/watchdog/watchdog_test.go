package watchdog

import (
	"fmt"
	"log"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestWatchdogStartStop(t *testing.T) {
	logger := log.New(os.Stderr, "test: ", 0)
	w := New(logger, nil)

	callCount := atomic.Int32{}
	w.AddCheck("test", 50*time.Millisecond, func() error {
		callCount.Add(1)
		return nil
	})

	w.Start()
	if !w.IsRunning() {
		t.Error("watchdog should be running")
	}

	time.Sleep(150 * time.Millisecond)
	w.Stop()

	if w.IsRunning() {
		t.Error("watchdog should be stopped")
	}

	count := callCount.Load()
	if count < 2 {
		t.Errorf("check should have run at least twice, got %d", count)
	}
}

func TestWatchdogDoubleStartStop(t *testing.T) {
	logger := log.New(os.Stderr, "test: ", 0)
	w := New(logger, nil)
	w.AddCheck("noop", time.Hour, func() error { return nil })

	w.Start()
	w.Start() // Should be a no-op

	w.Stop()
	w.Stop() // Should be a no-op
}

func TestWatchdogFailureNotification(t *testing.T) {
	logger := log.New(os.Stderr, "test: ", 0)

	failReason := make(chan string, 10)
	onFail := func(reason string) {
		failReason <- reason
	}

	w := New(logger, onFail)
	w.AddCheck("hw-check", 50*time.Millisecond, func() error {
		return fmt.Errorf("hardware mismatch")
	})

	w.Start()

	select {
	case reason := <-failReason:
		if reason == "" {
			t.Error("expected non-empty failure reason")
		}
	case <-time.After(1 * time.Second):
		t.Error("timed out waiting for failure notification")
	}

	w.Stop()
}

func TestWatchdogMultipleChecks(t *testing.T) {
	logger := log.New(os.Stderr, "test: ", 0)

	hwCount := atomic.Int32{}
	licCount := atomic.Int32{}

	w := New(logger, nil)
	w.AddCheck("hardware", 50*time.Millisecond, func() error {
		hwCount.Add(1)
		return nil
	})
	w.AddCheck("license", 50*time.Millisecond, func() error {
		licCount.Add(1)
		return nil
	})

	w.Start()
	time.Sleep(150 * time.Millisecond)
	w.Stop()

	if hwCount.Load() < 2 {
		t.Errorf("hardware check count = %d, want >= 2", hwCount.Load())
	}
	if licCount.Load() < 2 {
		t.Errorf("license check count = %d, want >= 2", licCount.Load())
	}
}

func TestWatchdogImmediateCheck(t *testing.T) {
	logger := log.New(os.Stderr, "test: ", 0)

	called := make(chan struct{}, 1)
	w := New(logger, nil)
	w.AddCheck("immediate", time.Hour, func() error {
		select {
		case called <- struct{}{}:
		default:
		}
		return nil
	})

	w.Start()

	select {
	case <-called:
		// Check ran immediately
	case <-time.After(1 * time.Second):
		t.Error("check should run immediately on start")
	}

	w.Stop()
}
