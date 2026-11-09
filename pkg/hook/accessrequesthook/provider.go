package accessrequesthook

import (
	"context"
	"time"
)

// AccessProvider is the interface that JIT access platforms implement.
type AccessProvider interface {
	Ensure(ctx context.Context, req *EnsureRequest) (*EnsureResponse, error)
	Login(ctx context.Context) error
	RequestURL(accessRequestID string) string
}

type EnsureRequest struct {
	Entitlements  []EntitlementInput
	Justification Justification
	DryRun        bool
}

type EntitlementInput struct {
	Target   string
	Role     string
	Duration *time.Duration
}

type Justification struct {
	Reason      string
	Attachments []string
}

type EnsureResponse struct {
	Grants      []GrantResult
	Validation  *ValidationInfo
	Diagnostics []Diagnostic
}

type GrantResult struct {
	ID                 string
	Name               string
	Status             GrantStatus
	Change             GrantChange
	Approved           bool
	Duration           time.Duration
	ExpiresAt          *time.Time
	ActivatedAt        *time.Time
	AccessRequestID    string
	ProvisioningStatus string
	Extension          *Extension
}

type Extension struct {
	ExtensionDuration time.Duration
}

type ValidationInfo struct {
	HasReason     bool
	HasJiraTicket bool
}

type Diagnostic struct {
	Level   string
	Message string
}

type GrantStatus string

const (
	GrantStatusActive      GrantStatus = "active"
	GrantStatusPending     GrantStatus = "pending"
	GrantStatusClosed      GrantStatus = "closed"
	GrantStatusUnspecified  GrantStatus = "unspecified"
)

// Unauthorized is an interface that errors can implement to indicate
// that the user needs to re-authenticate.
type Unauthorized interface {
	IsUnauthorized() bool
}

type GrantChange string

const (
	GrantChangeNone               GrantChange = "none"
	GrantChangeActivated          GrantChange = "activated"
	GrantChangeExtended           GrantChange = "extended"
	GrantChangeRequested          GrantChange = "requested"
	GrantChangeProvisioningFailed GrantChange = "provisioning_failed"
	GrantChangeUnspecified        GrantChange = ""
)
