// Package downstream contains the downstream delivery targets. Each target is
// an independent sink: one target failing must not block the others.
package downstream

import (
	"context"

	"github.com/highcumontoa/audit-log-router-go/event"
)

// Target is a downstream delivery destination.
type Target interface {
	// Name returns the unique target name referenced by routing rules.
	Name() string
	// Deliver attempts to deliver one (already compliance-processed) event.
	// It must be safe for concurrent use, and implementations must ensure the
	// same event ID is persisted at most once across retries/restarts.
	Deliver(ctx context.Context, ev event.Event) error
	// Healthy reports whether the target currently accepts traffic.
	Healthy() bool
	// Close releases any resources held by the target.
	Close() error
}
