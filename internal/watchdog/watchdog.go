package watchdog

import (
	"log"
	"sync"
	"time"
)

// CheckFunc is a function that performs a health check.
// Returns an error if the check fails.
type CheckFunc func() error

// NotifyFunc is called when a check fails.
type NotifyFunc func(reason string)

// Check represents a periodic health check.
type Check struct {
	Name     string
	Interval time.Duration
	Fn       CheckFunc
}

// Watchdog runs periodic health checks and notifies on failure.
type Watchdog struct {
	checks   []Check
	onFail   NotifyFunc
	logger   *log.Logger
	stopCh   chan struct{}
	wg       sync.WaitGroup
	mu       sync.Mutex
	running  bool
}

// New creates a new Watchdog.
func New(logger *log.Logger, onFail NotifyFunc) *Watchdog {
	return &Watchdog{
		onFail: onFail,
		logger: logger,
		stopCh: make(chan struct{}),
	}
}

// AddCheck registers a periodic check.
func (w *Watchdog) AddCheck(name string, interval time.Duration, fn CheckFunc) {
	w.checks = append(w.checks, Check{
		Name:     name,
		Interval: interval,
		Fn:       fn,
	})
}

// Start begins all watchdog checks in background goroutines.
func (w *Watchdog) Start() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.running {
		return
	}
	w.running = true

	for _, check := range w.checks {
		w.wg.Add(1)
		go w.runCheck(check)
	}

	w.logger.Printf("watchdog: started %d checks", len(w.checks))
}

// Stop signals all checks to stop and waits for them to finish.
func (w *Watchdog) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.running {
		return
	}
	w.running = false

	close(w.stopCh)
	w.wg.Wait()
	w.logger.Println("watchdog: stopped")
}

// IsRunning returns whether the watchdog is active.
func (w *Watchdog) IsRunning() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.running
}

func (w *Watchdog) runCheck(check Check) {
	defer w.wg.Done()

	ticker := time.NewTicker(check.Interval)
	defer ticker.Stop()

	// Run immediately on start
	if err := check.Fn(); err != nil {
		w.logger.Printf("watchdog: %s check failed: %v", check.Name, err)
		if w.onFail != nil {
			w.onFail(check.Name + ": " + err.Error())
		}
	}

	for {
		select {
		case <-w.stopCh:
			return
		case <-ticker.C:
			if err := check.Fn(); err != nil {
				w.logger.Printf("watchdog: %s check failed: %v", check.Name, err)
				if w.onFail != nil {
					w.onFail(check.Name + ": " + err.Error())
				}
			}
		}
	}
}
