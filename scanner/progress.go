package scanner

import (
	"fmt"
	"os"
	"time"
)

// Progress displays a live status line on stderr during a scan.
// It reads atomic counters from the Scanner and refreshes periodically.
type Progress struct {
	scanner   *Scanner
	totalCreds int64 // total credential pairs per target (users × passwords)
	startTime  time.Time
	stopCh     chan struct{}
	doneCh     chan struct{}
}

// NewProgress creates a progress reporter for the given scanner.
// totalCreds is len(usernames) * len(passwords).
func NewProgress(s *Scanner, totalCreds int64) *Progress {
	return &Progress{
		scanner:    s,
		totalCreds: totalCreds,
		startTime:  time.Now(),
		stopCh:     make(chan struct{}),
		doneCh:     make(chan struct{}),
	}
}

// Start begins the progress display loop in a goroutine.
func (p *Progress) Start() {
	go p.run()
}

// Stop halts the progress display and clears the status line.
func (p *Progress) Stop() {
	close(p.stopCh)
	<-p.doneCh
}

// Clear erases the current progress line from the terminal.
// Safe to call from other goroutines (e.g., the logger).
func (p *Progress) Clear() {
	fmt.Fprintf(os.Stderr, "\r\033[K")
}

func (p *Progress) run() {
	defer close(p.doneCh)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopCh:
			// clear the status line
			fmt.Fprintf(os.Stderr, "\r\033[K")
			return
		case <-ticker.C:
			p.render()
		}
	}
}

func (p *Progress) render() {
	attempts := p.scanner.Attempts.Load()
	successes := p.scanner.Successes.Load()
	elapsed := time.Since(p.startTime)

	// calculate speed (attempts per second)
	var speed float64
	if elapsed.Seconds() > 0 {
		speed = float64(attempts) / elapsed.Seconds()
	}

	// format elapsed time
	elapsedStr := formatDuration(elapsed)

	// build status line
	line := fmt.Sprintf("\r\033[K[%s] %d attempts | %.1f/s | %d found",
		elapsedStr, attempts, speed, successes)

	// add ETA if we have speed and totalCreds info
	if speed > 0 && p.totalCreds > 0 && attempts < p.totalCreds {
		remaining := float64(p.totalCreds-attempts) / speed
		line += fmt.Sprintf(" | ETA %s", formatDuration(time.Duration(remaining)*time.Second))
	}

	fmt.Fprint(os.Stderr, line)
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh%02dm%02ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm%02ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}
