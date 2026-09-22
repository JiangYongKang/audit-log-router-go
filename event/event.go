// Package event defines the audit event model and the per-event processing
// results produced by the compliance engine and the downstream delivery layer.
package event

import "time"

// Event is a single audit record submitted to the router.
type Event struct {
	// ID uniquely identifies an event. It is used for duplicate detection
	// across downstream deliveries and process restarts.
	ID string

	// Type is the business event type (e.g. "login", "payment").
	Type string

	// OccurredAt is the time at which the audited action happened.
	OccurredAt time.Time

	// Fields holds the event payload. Field names are referenced by the
	// masking / required-field rules.
	Fields map[string]string

	// Targets optionally restricts the set of downstream target names.
	// When nil/empty the routing rules decide the targets.
	Targets []string
}

// Status is the compliance verdict of an event.
type Status int

const (
	// StatusAccepted means the event passed validation and was persisted.
	StatusAccepted Status = iota
	// StatusRejectedMissing means the event was rejected because a required
	// field was absent or empty.
	StatusRejectedMissing
	// StatusRejectedConflict means the event was rejected because the active
	// rule set contained a conflict that made a compliant result impossible.
	StatusRejectedConflict
)

func (s Status) String() string {
	switch s {
	case StatusAccepted:
		return "accepted"
	case StatusRejectedMissing:
		return "rejected:missing-field"
	case StatusRejectedConflict:
		return "rejected:rule-conflict"
	default:
		return "unknown"
	}
}

// IngestResult is returned to the producer after a Submit call.
type IngestResult struct {
	EventID string
	Status  Status
	// Reason is a machine-readable, distinguishable rejection reason. It must
	// never contain masked original field values; field names are allowed.
	Reason string
	// Duplicate is true when the event ID had already been persisted. The
	// submission is still acknowledged (idempotent accept) but no new event
	// or deliveries are created.
	Duplicate bool
}

// DeliveryState is the delivery state of one event for one downstream target.
type DeliveryState int

const (
	StatePending DeliveryState = iota
	StateDelivered
	StateFailed
	StateDead
)

func (s DeliveryState) String() string {
	switch s {
	case StatePending:
		return "pending"
	case StateDelivered:
		return "delivered"
	case StateFailed:
		return "failed"
	case StateDead:
		return "dead"
	default:
		return "unknown"
	}
}

// DeliveryRecord is the auditable delivery status of one event for one target.
type DeliveryRecord struct {
	EventID   string
	Target    string
	State     DeliveryState
	Attempts  int
	LastError string
	UpdatedAt time.Time
}
