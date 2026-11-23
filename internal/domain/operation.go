package domain

import (
	"time"

	"github.com/google/uuid"
)

type OperationStatus string

const (
	OperationStatusPending   OperationStatus = "PENDING"
	OperationStatusRunning   OperationStatus = "RUNNING"
	OperationStatusSucceeded OperationStatus = "SUCCEEDED"
	OperationStatusFailed    OperationStatus = "FAILED"
	OperationStatusCancelled OperationStatus = "CANCELLED"
)

func (s OperationStatus) IsValid() bool {
	switch s {
	case OperationStatusPending, OperationStatusRunning, OperationStatusSucceeded, OperationStatusFailed, OperationStatusCancelled:
		return true
	default:
		return false
	}
}

func (s OperationStatus) IsTerminal() bool {
	return s == OperationStatusSucceeded || s == OperationStatusFailed || s == OperationStatusCancelled
}

type OperationType string

const (
	OperationTypeWorkspaceIngress    OperationType = "WORKSPACE_INGRESS"
	OperationTypeProposalReconstruct OperationType = "PROPOSAL_RECONSTRUCT"
	OperationTypeProposalEvaluate    OperationType = "PROPOSAL_EVALUATE"
	OperationTypeProposalPublish     OperationType = "PROPOSAL_PUBLISH"
)

type Operation struct {
	ID            uuid.UUID       `json:"id"`
	OperationType OperationType   `json:"operation_type"`
	ResourceID    uuid.UUID       `json:"resource_id"`
	Status        OperationStatus `json:"status"`
	Attempts      int             `json:"attempts"`
	AvailableAt   time.Time       `json:"available_at"`
	LeaseUntil    *time.Time      `json:"lease_until,omitempty"`
	LastError     string          `json:"last_error,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
}
