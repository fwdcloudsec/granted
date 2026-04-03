package httpprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/common-fate/clio"
	"github.com/fwdcloudsec/granted/pkg/hook/accessrequesthook"
	"github.com/fwdcloudsec/granted/pkg/providercfg"
)

// HTTPProvider implements AccessProvider using REST/JSON calls.
type HTTPProvider struct {
	cfg    *providercfg.ProviderConfig
	client *http.Client
}

// New creates an HTTPProvider from a ProviderConfig.
func New(cfg *providercfg.ProviderConfig) *HTTPProvider {
	return &HTTPProvider{
		cfg:    cfg,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

// Ensure calls POST {apiURL}/v1/access/ensure.
func (p *HTTPProvider) Ensure(ctx context.Context, req *accessrequesthook.EnsureRequest) (*accessrequesthook.EnsureResponse, error) {
	apiReq := toAPIRequest(req)

	body, err := json.Marshal(apiReq)
	if err != nil {
		return nil, fmt.Errorf("marshalling ensure request: %w", err)
	}

	ensureURL := p.cfg.APIURL + "/v1/access/ensure"
	clio.Debugw("calling ensure endpoint", "url", ensureURL, "dry_run", req.DryRun)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, ensureURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("ensure request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, &UnauthorizedError{StatusCode: resp.StatusCode}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ensure endpoint returned HTTP %d", resp.StatusCode)
	}

	var apiResp apiEnsureResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("decoding ensure response: %w", err)
	}

	return fromAPIResponse(&apiResp), nil
}

// Login attempts OIDC authentication. For now, returns an error directing the user
// to authenticate via their browser.
func (p *HTTPProvider) Login(ctx context.Context) error {
	return fmt.Errorf("please authenticate via your browser at %s", p.cfg.AccessURL)
}

// RequestURL builds the URL for viewing an access request.
func (p *HTTPProvider) RequestURL(accessRequestID string) string {
	u, err := url.Parse(p.cfg.AccessURL)
	if err != nil {
		return fmt.Sprintf("%s/access/requests/%s", p.cfg.AccessURL, accessRequestID)
	}
	return u.JoinPath("access", "requests", accessRequestID).String()
}

// UnauthorizedError indicates the provider returned a 401, meaning the token
// is expired or invalid and the user needs to re-authenticate.
type UnauthorizedError struct {
	StatusCode int
}

func (e *UnauthorizedError) Error() string {
	return fmt.Sprintf("unauthorized (HTTP %d): token expired or invalid", e.StatusCode)
}

func (e *UnauthorizedError) IsUnauthorized() bool {
	return true
}

// IsUnauthorized checks whether an error is an UnauthorizedError.
func IsUnauthorized(err error) bool {
	_, ok := err.(*UnauthorizedError)
	return ok
}

// --- API wire types ---

type apiEnsureRequest struct {
	Entitlements  []apiEntitlementInput `json:"entitlements"`
	Justification apiJustification     `json:"justification"`
	DryRun        bool                 `json:"dry_run"`
}

type apiEntitlementInput struct {
	Target   string `json:"target"`
	Role     string `json:"role"`
	Duration string `json:"duration,omitempty"`
}

type apiJustification struct {
	Reason      string   `json:"reason,omitempty"`
	Attachments []string `json:"attachments,omitempty"`
}

type apiEnsureResponse struct {
	Grants      []apiGrantResult  `json:"grants"`
	Validation  *apiValidation    `json:"validation,omitempty"`
	Diagnostics []apiDiagnostic   `json:"diagnostics,omitempty"`
}

type apiGrantResult struct {
	ID                 string        `json:"id"`
	Name               string        `json:"name"`
	Status             string        `json:"status"`
	Change             string        `json:"change"`
	Approved           bool          `json:"approved"`
	Duration           string        `json:"duration"`
	ExpiresAt          *string       `json:"expires_at,omitempty"`
	ActivatedAt        *string       `json:"activated_at,omitempty"`
	AccessRequestID    string        `json:"access_request_id"`
	ProvisioningStatus string        `json:"provisioning_status,omitempty"`
	Extension          *apiExtension `json:"extension,omitempty"`
}

type apiExtension struct {
	ExtensionDuration string `json:"extension_duration"`
}

type apiValidation struct {
	HasReason     bool `json:"has_reason"`
	HasJiraTicket bool `json:"has_jira_ticket"`
}

type apiDiagnostic struct {
	Level   string `json:"level"`
	Message string `json:"message"`
}

func toAPIRequest(req *accessrequesthook.EnsureRequest) *apiEnsureRequest {
	apiReq := &apiEnsureRequest{
		DryRun: req.DryRun,
		Justification: apiJustification{
			Reason:      req.Justification.Reason,
			Attachments: req.Justification.Attachments,
		},
	}

	for _, e := range req.Entitlements {
		ent := apiEntitlementInput{
			Target: e.Target,
			Role:   e.Role,
		}
		if e.Duration != nil {
			ent.Duration = e.Duration.String()
		}
		apiReq.Entitlements = append(apiReq.Entitlements, ent)
	}

	return apiReq
}

func fromAPIResponse(resp *apiEnsureResponse) *accessrequesthook.EnsureResponse {
	result := &accessrequesthook.EnsureResponse{}

	if resp.Validation != nil {
		result.Validation = &accessrequesthook.ValidationInfo{
			HasReason:     resp.Validation.HasReason,
			HasJiraTicket: resp.Validation.HasJiraTicket,
		}
	}

	for _, d := range resp.Diagnostics {
		result.Diagnostics = append(result.Diagnostics, accessrequesthook.Diagnostic{
			Level:   d.Level,
			Message: d.Message,
		})
	}

	for _, g := range resp.Grants {
		grant := accessrequesthook.GrantResult{
			ID:                 g.ID,
			Name:               g.Name,
			Status:             accessrequesthook.GrantStatus(g.Status),
			Change:             accessrequesthook.GrantChange(g.Change),
			Approved:           g.Approved,
			AccessRequestID:    g.AccessRequestID,
			ProvisioningStatus: g.ProvisioningStatus,
		}

		if d, err := time.ParseDuration(g.Duration); err == nil {
			grant.Duration = d
		}

		if g.ExpiresAt != nil {
			if t, err := time.Parse(time.RFC3339, *g.ExpiresAt); err == nil {
				grant.ExpiresAt = &t
			}
		}

		if g.ActivatedAt != nil {
			if t, err := time.Parse(time.RFC3339, *g.ActivatedAt); err == nil {
				grant.ActivatedAt = &t
			}
		}

		if g.Extension != nil {
			if d, err := time.ParseDuration(g.Extension.ExtensionDuration); err == nil {
				grant.Extension = &accessrequesthook.Extension{
					ExtensionDuration: d,
				}
			}
		}

		result.Grants = append(result.Grants, grant)
	}

	return result
}
