package domain

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type AuditEvent struct {
	ID           uuid.UUID       `json:"id"`
	EventType    string          `json:"event_type"`
	ActorID      *uuid.UUID      `json:"actor_id,omitempty"`
	ResourceType string          `json:"resource_type"`
	ResourceID   uuid.UUID       `json:"resource_id"`
	Payload      json.RawMessage `json:"payload"`
	PreviousHash string          `json:"previous_hash,omitempty"`
	EventHash    string          `json:"event_hash"`
	CreatedAt    time.Time       `json:"created_at"`
}

type OutboxEvent struct {
	ID          uuid.UUID       `json:"id"`
	EventType   string          `json:"event_type"`
	AggregateID uuid.UUID       `json:"aggregate_id"`
	Payload     json.RawMessage `json:"payload"`
	CreatedAt   time.Time       `json:"created_at"`
	DeliveredAt *time.Time      `json:"delivered_at,omitempty"`
}

type auditHashInput struct {
	PreviousHash string          `json:"previous_hash"`
	ID           uuid.UUID       `json:"id"`
	EventType    string          `json:"event_type"`
	ActorID      *uuid.UUID      `json:"actor_id"`
	ResourceType string          `json:"resource_type"`
	ResourceID   uuid.UUID       `json:"resource_id"`
	Payload      json.RawMessage `json:"payload"`
	CreatedAt    string          `json:"created_at"`
}

// ComputeAuditEventHash calculates the deterministic SHA-256 chain hash linking previousHash and ev.
func ComputeAuditEventHash(previousHash string, ev AuditEvent) (string, error) {
	if ev.ID == uuid.Nil {
		return "", BadRequest("INVALID_AUDIT_EVENT", "audit event ID must not be nil")
	}
	if ev.EventType == "" || ev.ResourceType == "" || ev.ResourceID == uuid.Nil {
		return "", BadRequest("INVALID_AUDIT_EVENT", "audit event type and resource are required")
	}
	payload := ev.Payload
	if len(payload) == 0 {
		payload = json.RawMessage(`{}`)
	}
	canonicalPayload, err := CanonicalJSONBytes(payload)
	if err != nil {
		return "", err
	}
	in := auditHashInput{
		PreviousHash: previousHash,
		ID:           ev.ID,
		EventType:    ev.EventType,
		ActorID:      ev.ActorID,
		ResourceType: ev.ResourceType,
		ResourceID:   ev.ResourceID,
		Payload:      json.RawMessage(canonicalPayload),
		CreatedAt:    ev.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
	return CanonicalJSONDigest(in)
}
