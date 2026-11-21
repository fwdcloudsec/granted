package accessrequesthook

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/fwdcloudsec/granted/pkg/cfaws"
	"github.com/stretchr/testify/assert"
	"gopkg.in/ini.v1"
)

// fakeProvider is a configurable AccessProvider test double.
type fakeProvider struct {
	ensureResponses []*EnsureResponse // consumed in order across successive Ensure calls
	ensureErrs      []error
	ensureCalls     []*EnsureRequest
	loginErr        error
	loginCalls      int
	requestURLFunc  func(id string) string
}

func (f *fakeProvider) Ensure(ctx context.Context, req *EnsureRequest) (*EnsureResponse, error) {
	i := len(f.ensureCalls)
	// snapshot the request: NoEntitlementAccess reuses the same *EnsureRequest
	// pointer for its dry-run and apply calls, mutating DryRun in between.
	reqCopy := *req
	f.ensureCalls = append(f.ensureCalls, &reqCopy)

	var resp *EnsureResponse
	if i < len(f.ensureResponses) {
		resp = f.ensureResponses[i]
	} else if len(f.ensureResponses) > 0 {
		resp = f.ensureResponses[len(f.ensureResponses)-1]
	}

	var err error
	if i < len(f.ensureErrs) {
		err = f.ensureErrs[i]
	}
	return resp, err
}

func (f *fakeProvider) Login(ctx context.Context) error {
	f.loginCalls++
	return f.loginErr
}

func (f *fakeProvider) RequestURL(id string) string {
	if f.requestURLFunc != nil {
		return f.requestURLFunc(id)
	}
	return "https://access.example.com/requests/" + id
}

type unauthorizedErr struct{}

func (unauthorizedErr) Error() string        { return "unauthorized" }
func (unauthorizedErr) IsUnauthorized() bool { return true }

func newProfile(t *testing.T) *cfaws.Profile {
	t.Helper()
	p := &cfaws.Profile{Name: "test-profile"}
	p.AWSConfig.SSOAccountID = "123456789012"
	p.AWSConfig.SSORoleName = "Admin"
	return p
}

func TestNewHook(t *testing.T) {
	assert.Nil(t, NewHook(nil))

	fp := &fakeProvider{}
	h := NewHook(fp)
	if assert.NotNil(t, h) {
		assert.Equal(t, fp, h.Provider)
	}
}

func newProfileWithKeys(t *testing.T, keys map[string]string) *cfaws.Profile {
	t.Helper()
	f := ini.Empty()
	sec, err := f.NewSection("profile test")
	assert.NoError(t, err)
	for k, v := range keys {
		_, err := sec.NewKey(k, v)
		assert.NoError(t, err)
	}
	return &cfaws.Profile{Name: "test", RawConfig: sec}
}

func TestNewHookFromProfile(t *testing.T) {
	t.Run("no provider url returns nil, nil", func(t *testing.T) {
		h, err := NewHookFromProfile(newProfileWithKeys(t, nil), func(string) (AccessProvider, error) {
			t.Fatal("factory should not be called")
			return nil, nil
		})
		assert.NoError(t, err)
		assert.Nil(t, h)
	})

	t.Run("builds hook from granted_access_provider_url", func(t *testing.T) {
		p := newProfileWithKeys(t, map[string]string{"granted_access_provider_url": "https://provider.example.com"})
		var gotURL string
		fp := &fakeProvider{}
		h, err := NewHookFromProfile(p, func(u string) (AccessProvider, error) {
			gotURL = u
			return fp, nil
		})
		assert.NoError(t, err)
		if assert.NotNil(t, h) {
			assert.Equal(t, fp, h.Provider)
		}
		assert.Equal(t, "https://provider.example.com", gotURL)
	})

	t.Run("falls back to legacy common_fate_url", func(t *testing.T) {
		p := newProfileWithKeys(t, map[string]string{"common_fate_url": "https://legacy.example.com"})
		var gotURL string
		h, err := NewHookFromProfile(p, func(u string) (AccessProvider, error) {
			gotURL = u
			return &fakeProvider{}, nil
		})
		assert.NoError(t, err)
		assert.NotNil(t, h)
		assert.Equal(t, "https://legacy.example.com", gotURL)
	})

	t.Run("factory error propagates", func(t *testing.T) {
		p := newProfileWithKeys(t, map[string]string{"granted_access_provider_url": "https://provider.example.com"})
		h, err := NewHookFromProfile(p, func(string) (AccessProvider, error) {
			return nil, errors.New("boom")
		})
		assert.Nil(t, h)
		assert.ErrorContains(t, err, "boom")
	})
}

func TestShortDur(t *testing.T) {
	tests := []struct {
		name string
		d    time.Duration
		want string
	}{
		{"trims zero minutes off hours", 2 * time.Hour, "2h"},
		{"keeps non-zero minutes", 2*time.Hour + 30*time.Minute, "2h30m"},
		{"trims zero seconds off minutes", 5 * time.Minute, "5m"},
		{"durations over a minute round to the nearest minute", 90 * time.Second, "2m"},
		{"rounds sub-minute durations to seconds", 45*time.Second + 400*time.Millisecond, "45s"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ShortDur(tt.d))
		})
	}
}

func TestIsUnauthorized(t *testing.T) {
	assert.False(t, isUnauthorized(nil))
	assert.False(t, isUnauthorized(errors.New("some other error")))
	assert.True(t, isUnauthorized(unauthorizedErr{}))
	assert.True(t, isUnauthorized(errors.New("oauth2: token expired")))
	assert.True(t, isUnauthorized(errors.New("oauth2: invalid grant")))
	assert.True(t, isUnauthorized(errors.New(`oauth2: "token_expired"`)))
	assert.True(t, isUnauthorized(errors.New(`oauth2: "invalid_grant"`)))
}

func TestIsTerminal(t *testing.T) {
	// go test's stdin/stdout are not a tty, so this should reliably be false
	// in CI and most local runs; it mainly guards against a panic.
	assert.False(t, IsTerminal(^uintptr(0)))
}

func TestNoEntitlementAccess(t *testing.T) {
	t.Run("no changes and not waiting returns error", func(t *testing.T) {
		fp := &fakeProvider{
			ensureResponses: []*EnsureResponse{{Grants: []GrantResult{}}},
		}
		h := Hook{Provider: fp}

		retry, result, justActivated, err := h.NoEntitlementAccess(context.Background(), NoEntitlementAccessInput{
			Target: "AWS::Account::123", Role: "Admin",
		})
		assert.False(t, retry)
		assert.Nil(t, result)
		assert.False(t, justActivated)
		assert.ErrorContains(t, err, "no access changes")
	})

	t.Run("no changes but already active shortcuts to success", func(t *testing.T) {
		fp := &fakeProvider{
			ensureResponses: []*EnsureResponse{{
				Grants: []GrantResult{{Status: GrantStatusActive, Change: GrantChangeNone}},
			}},
		}
		h := Hook{Provider: fp}

		retry, result, justActivated, err := h.NoEntitlementAccess(context.Background(), NoEntitlementAccessInput{})
		assert.False(t, retry)
		assert.NotNil(t, result)
		assert.False(t, justActivated)
		assert.NoError(t, err)
	})

	t.Run("no changes with wait set returns retry", func(t *testing.T) {
		fp := &fakeProvider{
			ensureResponses: []*EnsureResponse{{Grants: []GrantResult{}}},
		}
		h := Hook{Provider: fp}

		retry, _, _, err := h.NoEntitlementAccess(context.Background(), NoEntitlementAccessInput{Wait: true})
		assert.True(t, retry)
		assert.NoError(t, err)
	})

	t.Run("unauthorized on dry run triggers login and retries", func(t *testing.T) {
		fp := &fakeProvider{
			ensureResponses: []*EnsureResponse{
				nil, // first (unauthorized) dry run call
				{Grants: []GrantResult{{Status: GrantStatusActive, Change: GrantChangeNone}}},
			},
			ensureErrs: []error{unauthorizedErr{}},
		}
		h := Hook{Provider: fp}

		_, result, _, err := h.NoEntitlementAccess(context.Background(), NoEntitlementAccessInput{})
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, 1, fp.loginCalls)
		assert.Len(t, fp.ensureCalls, 2)
	})

	t.Run("login failure propagates", func(t *testing.T) {
		fp := &fakeProvider{
			ensureErrs: []error{unauthorizedErr{}},
			loginErr:   errors.New("login failed"),
		}
		h := Hook{Provider: fp}

		_, _, _, err := h.NoEntitlementAccess(context.Background(), NoEntitlementAccessInput{})
		assert.ErrorContains(t, err, "login failed")
	})

	t.Run("activation with confirm bypasses prompt and applies changes", func(t *testing.T) {
		dryRunResp := &EnsureResponse{
			Grants: []GrantResult{{Name: "my-grant", Change: GrantChangeActivated, Duration: time.Hour}},
		}
		applyResp := &EnsureResponse{
			Grants: []GrantResult{{Name: "my-grant", Change: GrantChangeActivated, Duration: time.Hour}},
		}
		fp := &fakeProvider{ensureResponses: []*EnsureResponse{dryRunResp, applyResp}}
		h := Hook{Provider: fp}

		retry, result, justActivated, err := h.NoEntitlementAccess(context.Background(), NoEntitlementAccessInput{
			Confirm: true,
			Reason:  "testing",
		})
		assert.NoError(t, err)
		assert.True(t, retry)
		assert.True(t, justActivated)
		assert.NotNil(t, result)
		assert.Len(t, fp.ensureCalls, 2)
		assert.True(t, fp.ensureCalls[0].DryRun)
		assert.False(t, fp.ensureCalls[1].DryRun)
		assert.Equal(t, "testing", fp.ensureCalls[1].Justification.Reason)
	})

	t.Run("reason required but non-interactive terminal errors", func(t *testing.T) {
		fp := &fakeProvider{
			ensureResponses: []*EnsureResponse{{
				Grants:     []GrantResult{{Name: "my-grant", Change: GrantChangeActivated}},
				Validation: &ValidationInfo{HasReason: true},
			}},
		}
		h := Hook{Provider: fp}

		_, _, _, err := h.NoEntitlementAccess(context.Background(), NoEntitlementAccessInput{Confirm: true})
		assert.ErrorContains(t, err, "noninteractive terminal")
		assert.ErrorContains(t, err, "--reason")
	})

	t.Run("jira attachment required but non-interactive terminal errors", func(t *testing.T) {
		fp := &fakeProvider{
			ensureResponses: []*EnsureResponse{{
				Grants:     []GrantResult{{Name: "my-grant", Change: GrantChangeActivated}},
				Validation: &ValidationInfo{HasJiraTicket: true},
			}},
		}
		h := Hook{Provider: fp}

		_, _, _, err := h.NoEntitlementAccess(context.Background(), NoEntitlementAccessInput{Confirm: true, Reason: "testing"})
		assert.ErrorContains(t, err, "noninteractive terminal")
		assert.ErrorContains(t, err, "--attach")
	})

	t.Run("without confirm and non-interactive terminal errors", func(t *testing.T) {
		fp := &fakeProvider{
			ensureResponses: []*EnsureResponse{{
				Grants: []GrantResult{{Name: "my-grant", Change: GrantChangeActivated}},
			}},
		}
		h := Hook{Provider: fp}

		_, _, _, err := h.NoEntitlementAccess(context.Background(), NoEntitlementAccessInput{Reason: "testing"})
		assert.ErrorContains(t, err, "noninteractive terminal")
		assert.ErrorContains(t, err, "--confirm")
	})

	t.Run("requires approval without wait returns error", func(t *testing.T) {
		fp := &fakeProvider{
			ensureResponses: []*EnsureResponse{
				{Grants: []GrantResult{{Name: "my-grant", Change: GrantChangeRequested}}},
				{Grants: []GrantResult{{Name: "my-grant", Change: GrantChangeRequested}}},
			},
		}
		h := Hook{Provider: fp}

		retry, result, _, err := h.NoEntitlementAccess(context.Background(), NoEntitlementAccessInput{Confirm: true, Reason: "testing"})
		assert.False(t, retry)
		assert.Nil(t, result)
		assert.ErrorContains(t, err, "require approval")
	})

	t.Run("requires approval with wait returns retry", func(t *testing.T) {
		fp := &fakeProvider{
			ensureResponses: []*EnsureResponse{
				{Grants: []GrantResult{{Name: "my-grant", Change: GrantChangeRequested}}},
				{Grants: []GrantResult{{Name: "my-grant", Change: GrantChangeRequested}}},
			},
		}
		h := Hook{Provider: fp}

		retry, result, _, err := h.NoEntitlementAccess(context.Background(), NoEntitlementAccessInput{Confirm: true, Reason: "testing", Wait: true})
		assert.True(t, retry)
		assert.NotNil(t, result)
		assert.NoError(t, err)
	})

	t.Run("provisioning failed returns error", func(t *testing.T) {
		fp := &fakeProvider{
			ensureResponses: []*EnsureResponse{
				{Grants: []GrantResult{{Name: "my-grant", Change: GrantChangeProvisioningFailed}}},
				{Grants: []GrantResult{{Name: "my-grant", Change: GrantChangeProvisioningFailed}}},
			},
		}
		h := Hook{Provider: fp}

		_, _, _, err := h.NoEntitlementAccess(context.Background(), NoEntitlementAccessInput{Confirm: true, Reason: "testing"})
		assert.ErrorContains(t, err, "provisioning failed")
	})

	t.Run("pending grant without wait returns error", func(t *testing.T) {
		fp := &fakeProvider{
			ensureResponses: []*EnsureResponse{
				// dry run has a change so we proceed to the real ensure call
				{Grants: []GrantResult{{Name: "my-grant", Change: GrantChangeActivated}}},
				{Grants: []GrantResult{{Name: "my-grant", Change: GrantChangeNone, Status: GrantStatusPending}}},
			},
		}
		h := Hook{Provider: fp}

		retry, result, _, err := h.NoEntitlementAccess(context.Background(), NoEntitlementAccessInput{Confirm: true, Reason: "testing"})
		assert.False(t, retry)
		assert.Nil(t, result)
		assert.ErrorContains(t, err, "pending approval")
	})

	t.Run("closed grant returns error", func(t *testing.T) {
		fp := &fakeProvider{
			ensureResponses: []*EnsureResponse{
				{Grants: []GrantResult{{Name: "my-grant", Change: GrantChangeActivated}}},
				{Grants: []GrantResult{{Name: "my-grant", Change: GrantChangeNone, Status: GrantStatusClosed}}},
			},
		}
		h := Hook{Provider: fp}

		_, _, _, err := h.NoEntitlementAccess(context.Background(), NoEntitlementAccessInput{Confirm: true, Reason: "testing"})
		assert.ErrorContains(t, err, "grant was closed")
	})

	t.Run("unspecified status returns error", func(t *testing.T) {
		fp := &fakeProvider{
			ensureResponses: []*EnsureResponse{
				{Grants: []GrantResult{{Name: "my-grant", Change: GrantChangeActivated}}},
				{Grants: []GrantResult{{Name: "my-grant", Change: GrantChangeNone, Status: GrantStatusUnspecified}}},
			},
		}
		h := Hook{Provider: fp}

		_, _, _, err := h.NoEntitlementAccess(context.Background(), NoEntitlementAccessInput{Confirm: true, Reason: "testing"})
		assert.ErrorContains(t, err, "unspecified state")
	})

	t.Run("already active grant retries", func(t *testing.T) {
		fp := &fakeProvider{
			ensureResponses: []*EnsureResponse{
				{Grants: []GrantResult{{Name: "my-grant", Change: GrantChangeActivated}}},
				{Grants: []GrantResult{{Name: "my-grant", Change: GrantChangeNone, Status: GrantStatusActive}}},
			},
		}
		h := Hook{Provider: fp}

		retry, result, _, err := h.NoEntitlementAccess(context.Background(), NoEntitlementAccessInput{Confirm: true, Reason: "testing"})
		assert.True(t, retry)
		assert.NotNil(t, result)
		assert.NoError(t, err)
	})

	t.Run("ensure error on apply propagates", func(t *testing.T) {
		fp := &fakeProvider{
			ensureResponses: []*EnsureResponse{
				{Grants: []GrantResult{{Name: "my-grant", Change: GrantChangeActivated}}},
				nil,
			},
			ensureErrs: []error{nil, errors.New("apply failed")},
		}
		h := Hook{Provider: fp}

		_, _, _, err := h.NoEntitlementAccess(context.Background(), NoEntitlementAccessInput{Confirm: true, Reason: "testing"})
		assert.ErrorContains(t, err, "apply failed")
	})

	t.Run("dry run ensure error propagates", func(t *testing.T) {
		fp := &fakeProvider{ensureErrs: []error{errors.New("dry run failed")}}
		h := Hook{Provider: fp}

		_, _, _, err := h.NoEntitlementAccess(context.Background(), NoEntitlementAccessInput{})
		assert.ErrorContains(t, err, "dry run failed")
	})
}

func TestNoAccess(t *testing.T) {
	t.Run("nil provider is a no-op", func(t *testing.T) {
		h := Hook{}
		retry, justActivated, err := h.NoAccess(context.Background(), NoAccessInput{Profile: newProfile(t)})
		assert.False(t, retry)
		assert.False(t, justActivated)
		assert.NoError(t, err)
	})

	t.Run("delegates to NoEntitlementAccess with profile target/role", func(t *testing.T) {
		fp := &fakeProvider{
			ensureResponses: []*EnsureResponse{{Grants: []GrantResult{{Status: GrantStatusActive, Change: GrantChangeNone}}}},
		}
		h := Hook{Provider: fp}

		_, _, err := h.NoAccess(context.Background(), NoAccessInput{Profile: newProfile(t)})
		assert.NoError(t, err)
		if assert.Len(t, fp.ensureCalls, 1) {
			assert.Equal(t, "AWS::Account::123456789012", fp.ensureCalls[0].Entitlements[0].Target)
			assert.Equal(t, "Admin", fp.ensureCalls[0].Entitlements[0].Role)
		}
	})
}

func TestRetryAccess(t *testing.T) {
	t.Run("nil provider is a no-op", func(t *testing.T) {
		h := Hook{}
		err := h.RetryAccess(context.Background(), NoAccessInput{Profile: newProfile(t)})
		assert.NoError(t, err)
	})

	t.Run("delegates with profile target/role", func(t *testing.T) {
		fp := &fakeProvider{
			ensureResponses: []*EnsureResponse{{Grants: []GrantResult{{Status: GrantStatusActive, ActivatedAt: timePtr(time.Now()), Approved: true}}}},
		}
		h := Hook{Provider: fp}

		err := h.RetryAccess(context.Background(), NoAccessInput{Profile: newProfile(t), StartTime: time.Now()})
		assert.NoError(t, err)
		if assert.Len(t, fp.ensureCalls, 1) {
			assert.Equal(t, "AWS::Account::123456789012", fp.ensureCalls[0].Entitlements[0].Target)
		}
	})
}

func timePtr(t time.Time) *time.Time { return &t }

func TestRetryNoEntitlementAccess(t *testing.T) {
	t.Run("all approved and activated returns nil error", func(t *testing.T) {
		fp := &fakeProvider{
			ensureResponses: []*EnsureResponse{{
				Grants: []GrantResult{{Approved: true, ActivatedAt: timePtr(time.Now())}},
			}},
		}
		h := Hook{Provider: fp}

		res, err := h.RetryNoEntitlementAccess(context.Background(), NoEntitlementAccessInput{StartTime: time.Now()})
		assert.NoError(t, err)
		assert.NotNil(t, res)
	})

	t.Run("active grant short-circuits approval checks", func(t *testing.T) {
		fp := &fakeProvider{
			ensureResponses: []*EnsureResponse{{
				Grants: []GrantResult{{Status: GrantStatusActive}},
			}},
		}
		h := Hook{Provider: fp}

		_, err := h.RetryNoEntitlementAccess(context.Background(), NoEntitlementAccessInput{StartTime: time.Now()})
		assert.NoError(t, err)
	})

	t.Run("not yet approved returns waiting error", func(t *testing.T) {
		fp := &fakeProvider{
			ensureResponses: []*EnsureResponse{{
				Grants: []GrantResult{{Approved: false}},
			}},
		}
		h := Hook{Provider: fp}

		_, err := h.RetryNoEntitlementAccess(context.Background(), NoEntitlementAccessInput{StartTime: time.Now()})
		assert.ErrorContains(t, err, "waiting on all grants")
	})

	t.Run("approved but not yet activated returns waiting error", func(t *testing.T) {
		fp := &fakeProvider{
			ensureResponses: []*EnsureResponse{{
				Grants: []GrantResult{{Approved: true, ActivatedAt: nil}},
			}},
		}
		h := Hook{Provider: fp}

		_, err := h.RetryNoEntitlementAccess(context.Background(), NoEntitlementAccessInput{StartTime: time.Now()})
		assert.ErrorContains(t, err, "waiting on all grants")
	})

	t.Run("ensure error propagates", func(t *testing.T) {
		fp := &fakeProvider{ensureErrs: []error{errors.New("ensure failed")}}
		h := Hook{Provider: fp}

		_, err := h.RetryNoEntitlementAccess(context.Background(), NoEntitlementAccessInput{StartTime: time.Now()})
		assert.ErrorContains(t, err, "ensure failed")
	})
}

func TestDryRun_JSONOutput(t *testing.T) {
	fp := &fakeProvider{
		ensureResponses: []*EnsureResponse{{Grants: []GrantResult{{Change: GrantChangeActivated}}}},
	}
	h := Hook{Provider: fp}

	req := &EnsureRequest{}
	hasChanges, res, err := h.dryRun(context.Background(), req, true, false)
	assert.False(t, hasChanges)
	assert.Nil(t, res)
	assert.ErrorContains(t, err, "--output=json")
}

func TestDebugJSON(t *testing.T) {
	got := debugJSON(map[string]string{"a": "b"})
	assert.Equal(t, `{"a":"b"}`, got)
}

func TestPrintDiagnostics_DoesNotPanic(t *testing.T) {
	assert.NotPanics(t, func() {
		printDiagnostics([]Diagnostic{
			{Level: "error", Message: "e"},
			{Level: "warning", Message: "w"},
			{Level: "info", Message: "i"},
		})
	})
}
