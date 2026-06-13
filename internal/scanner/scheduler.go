// Package scanner — scheduled scan runner.
// Periodically checks for due scheduled scans and executes them.
// This drives the recurring value proposition: customers pay monthly
// for automated, ongoing security monitoring.
package scanner

import (
	"log"
	"time"

	"ke-scan/internal/db"
)

// Scheduler manages recurring scan execution.
type Scheduler struct {
	db     *db.DB
	engine *Engine
	stopCh chan struct{}
}

// NewScheduler creates a new scheduled scan runner.
func NewScheduler(database *db.DB, engine *Engine) *Scheduler {
	return &Scheduler{
		db:     database,
		engine: engine,
		stopCh: make(chan struct{}),
	}
}

// Start begins the scheduler loop in a goroutine.
// Checks every minute for scheduled scans that are due.
func (s *Scheduler) Start() {
	log.Println("Scheduled scan runner started (checking every 60s)")
	go s.loop()
}

// Stop signals the scheduler to stop.
func (s *Scheduler) Stop() {
	close(s.stopCh)
	log.Println("Scheduled scan runner stopped")
}

func (s *Scheduler) loop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	// Run an initial check immediately
	s.checkAndRun()

	for {
		select {
		case <-ticker.C:
			s.checkAndRun()
		case <-s.stopCh:
			return
		}
	}
}

func (s *Scheduler) checkAndRun() {
	due, err := s.db.GetScheduledScansDue()
	if err != nil {
		log.Printf("Scheduler: error fetching due scans: %v", err)
		return
	}

	if len(due) == 0 {
		return
	}

	log.Printf("Scheduler: %d scheduled scans due", len(due))

	for _, sched := range due {
		s.executeScheduledScan(sched)
	}
}

func (s *Scheduler) executeScheduledScan(sched *db.ScheduledScan) {
	// Get the domain name for the target URL
	domain, err := s.db.GetDomainByID(sched.DomainID)
	if err != nil || domain == nil {
		log.Printf("Scheduler: cannot find domain %d for scheduled scan %d", sched.DomainID, sched.ID)
		return
	}

	targetURL := "https://" + domain.Domain

	// Create a new scan record
	scan, err := s.db.CreateScan(sched.TenantID, targetURL, sched.ScanType)
	if err != nil {
		log.Printf("Scheduler: failed to create scan for scheduled %d: %v", sched.ID, err)
		return
	}

	log.Printf("Scheduler: executing scheduled scan %d → scan %d for %s", sched.ID, scan.ID, targetURL)

	// Link the scan to the domain
	s.db.Exec(`UPDATE scans SET domain_id = ? WHERE id = ?`, sched.DomainID, scan.ID)

	// Run the scan (this blocks until complete — it runs in the scheduler goroutine)
	s.engine.RunScan(scan.ID, targetURL, sched.ScanType)

	// Calculate next run time based on frequency
	nextRun := calculateNextRun(sched.Frequency)

	// Update the scheduled scan record
	if err := s.db.UpdateScheduledScanAfterRun(sched.ID, scan.ID, nextRun); err != nil {
		log.Printf("Scheduler: failed to update scheduled scan %d: %v", sched.ID, err)
	}

	log.Printf("Scheduler: next run for scheduled scan %d: %s", sched.ID, nextRun.Format(time.RFC3339))
}

// calculateNextRun computes the next execution time based on the frequency.
func calculateNextRun(frequency string) time.Time {
	now := time.Now()
	switch frequency {
	case "daily":
		return now.AddDate(0, 0, 1)
	case "monthly":
		return now.AddDate(0, 1, 0)
	default: // weekly
		return now.AddDate(0, 0, 7)
	}
}
