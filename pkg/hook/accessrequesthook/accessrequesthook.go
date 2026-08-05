package accessrequesthook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/briandowns/spinner"
	"github.com/common-fate/clio"
	"github.com/fatih/color"
	"github.com/fwdcloudsec/granted/pkg/cfaws"
	"github.com/mattn/go-isatty"
)

type Hook struct {
	Provider AccessProvider
}

// NewHook creates a Hook with the given provider.
// Callers should construct the appropriate AccessProvider (e.g., httpprovider.New)
// and pass it here. Returns nil if no provider is given.
func NewHook(provider AccessProvider) *Hook {
	if provider == nil {
		return nil
	}
	return &Hook{Provider: provider}
}

// NewHookFromProfile creates a Hook configured from the profile's provider URL.
// Returns (nil, nil) if no provider is configured on the profile.
// This is a convenience function that requires the caller to provide a
// factory function to avoid import cycles.
func NewHookFromProfile(profile *cfaws.Profile, factory func(providerURL string) (AccessProvider, error)) (*Hook, error) {
	providerURL := getProviderURL(profile)
	if providerURL == "" {
		return nil, nil
	}
	provider, err := factory(providerURL)
	if err != nil {
		return nil, err
	}
	return &Hook{Provider: provider}, nil
}

// getProviderURL reads the access provider URL from a profile's raw config.
func getProviderURL(profile *cfaws.Profile) string {
	if profile == nil || profile.RawConfig == nil {
		return ""
	}
	for _, key := range []string{"granted_access_provider_url", "common_fate_url"} {
		if profile.RawConfig.HasKey(key) {
			k, err := profile.RawConfig.GetKey(key)
			if err != nil {
				continue
			}
			if k.Value() != "" {
				return k.Value()
			}
		}
	}
	return ""
}

type NoAccessInput struct {
	Profile     *cfaws.Profile
	Reason      string
	Attachments []string
	Duration    *time.Duration
	Confirm     bool
	Wait        bool
	StartTime   time.Time
}

func (h Hook) NoAccess(ctx context.Context, input NoAccessInput) (retry bool, justActivated bool, err error) {
	if h.Provider == nil {
		clio.Debugw("no access provider configured, skipping access request hook")
		return false, false, nil
	}

	target := fmt.Sprintf("AWS::Account::%s", input.Profile.AWSConfig.SSOAccountID)
	role := input.Profile.AWSConfig.SSORoleName

	clio.Infof("You don't currently have access to %s, checking if we can request access...\t[target=%s, role=%s]", input.Profile.Name, target, role)

	retry, _, justActivated, err = h.NoEntitlementAccess(ctx, NoEntitlementAccessInput{
		Target:      target,
		Role:        role,
		Reason:      input.Reason,
		Duration:    input.Duration,
		Confirm:     input.Confirm,
		Wait:        input.Wait,
		StartTime:   input.StartTime,
		Attachments: input.Attachments,
	})

	return retry, justActivated, err
}

type NoEntitlementAccessInput struct {
	Target      string
	Role        string
	Reason      string
	Attachments []string
	Duration    *time.Duration
	Confirm     bool
	Wait        bool
	StartTime   time.Time
}

func (h Hook) NoEntitlementAccess(ctx context.Context, input NoEntitlementAccessInput) (retry bool, result *EnsureResponse, justActivated bool, err error) {
	justActivated = false

	req := EnsureRequest{
		Entitlements: []EntitlementInput{
			{
				Target:   input.Target,
				Role:     input.Role,
				Duration: input.Duration,
			},
		},
		Justification: Justification{},
	}

	hasChanges, result, err := h.dryRun(ctx, &req, false, input.Confirm)
	if isUnauthorized(err) {
		clio.Debugw("prompting user login because token is expired", "error_details", err.Error())
		clio.Infof("You need to log in to your access provider")

		err = h.Provider.Login(ctx)
		if err != nil {
			return false, nil, justActivated, err
		}

		hasChanges, result, err = h.dryRun(ctx, &req, false, input.Confirm)
	}

	if err != nil {
		return false, nil, justActivated, err
	}
	if !hasChanges {
		if result != nil && len(result.Grants) == 1 && result.Grants[0].Status == GrantStatusActive {
			return false, result, justActivated, nil
		}
		if input.Wait {
			return true, result, justActivated, nil
		}
		return false, nil, justActivated, errors.New("no access changes")
	}

	req.DryRun = false

	if input.Reason != "" {
		req.Justification.Reason = input.Reason
	} else {
		if result.Validation != nil && result.Validation.HasReason {
			if !IsTerminal(os.Stdin.Fd()) {
				return false, nil, justActivated, errors.New("detected a noninteractive terminal: a reason is required to make this access request, to apply the planned changes please re-run with the --reason flag")
			}

			var customReason string
			msg := "Reason for access (Required)"
			reasonPrompt := &survey.Input{
				Message: msg,
				Help:    "Will be stored in audit trails and associated with your request",
			}
			withStdio := survey.WithStdio(os.Stdin, os.Stderr, os.Stderr)
			err = survey.AskOne(reasonPrompt, &customReason, withStdio, survey.WithValidator(survey.Required))
			if err != nil {
				return false, nil, justActivated, err
			}

			req.Justification.Reason = customReason
		}
	}

	if len(input.Attachments) > 0 {
		req.Justification.Attachments = input.Attachments
	} else {
		if result.Validation != nil && result.Validation.HasJiraTicket {
			if !IsTerminal(os.Stdin.Fd()) {
				return false, nil, justActivated, errors.New("detected a noninteractive terminal: a jira ticket attachment is required to make this access request, to apply the planned changes please re-run with the --attach flag")
			}

			var attachment string
			msg := "Jira ticket attachment for access (Required)"
			reasonPrompt := &survey.Input{
				Message: msg,
				Help:    "Will be stored in audit trails and associated with your request",
			}
			withStdio := survey.WithStdio(os.Stdin, os.Stderr, os.Stderr)
			err = survey.AskOne(reasonPrompt, &attachment, withStdio, survey.WithValidator(survey.Required))
			if err != nil {
				return false, nil, justActivated, err
			}

			req.Justification.Attachments = append(req.Justification.Attachments, attachment)
		}
	}

	si := spinner.New(spinner.CharSets[14], 100*time.Millisecond)
	si.Suffix = " ensuring access..."
	si.Writer = os.Stderr
	si.Start()

	res, err := h.Provider.Ensure(ctx, &req)
	if err != nil {
		si.Stop()
		return false, nil, justActivated, err
	}
	si.Stop()

	printDiagnostics(res.Diagnostics)

	clio.Debugw("Ensure response", "response", debugJSON(res))

	for _, g := range res.Grants {
		exp := ShortDur(g.Duration)

		switch g.Change {
		case GrantChangeActivated:
			_, _ = color.New(color.BgHiGreen).Fprintf(os.Stderr, "[ACTIVATED]")
			_, _ = color.New(color.FgGreen).Fprintf(os.Stderr, " %s was activated for %s: %s\n", g.Name, exp, h.Provider.RequestURL(g.AccessRequestID))
			retry = true
			justActivated = true
			continue

		case GrantChangeExtended:
			extendedTime := ""
			if g.Extension != nil {
				extendedTime = ShortDur(g.Extension.ExtensionDuration)
			}
			_, _ = color.New(color.BgBlue).Fprintf(os.Stderr, "[EXTENDED]")
			_, _ = color.New(color.FgBlue).Fprintf(os.Stderr, " %s was extended for another %s: %s\n", g.Name, extendedTime, h.Provider.RequestURL(g.AccessRequestID))
			_, _ = color.New(color.FgGreen).Printf(" %s will now expire in %s\n", g.Name, exp)
			retry = true
			continue

		case GrantChangeRequested:
			_, _ = color.New(color.BgHiYellow, color.FgBlack).Fprintf(os.Stderr, "[REQUESTED]")
			_, _ = color.New(color.FgYellow).Fprintf(os.Stderr, " %s requires approval: %s\n", g.Name, h.Provider.RequestURL(g.AccessRequestID))
			if input.Wait {
				return true, res, justActivated, nil
			}
			return false, nil, justActivated, errors.New("applying access was attempted but the resources requested require approval before activation")

		case GrantChangeProvisioningFailed:
			_, _ = color.New(color.FgRed).Fprintf(os.Stderr, "[ERROR] %s failed provisioning: %s\n", g.Name, h.Provider.RequestURL(g.AccessRequestID))
			return false, nil, justActivated, errors.New("access provisioning failed")
		}

		switch g.Status {
		case GrantStatusActive:
			if g.ExpiresAt != nil {
				exp = ShortDur(time.Until(*g.ExpiresAt))
			}
			_, _ = color.New(color.FgGreen).Fprintf(os.Stderr, "[ACTIVE] %s is already active for the next %s: %s\n", g.Name, exp, h.Provider.RequestURL(g.AccessRequestID))
			retry = true
			continue

		case GrantStatusPending:
			_, _ = color.New(color.FgWhite).Fprintf(os.Stderr, "[PENDING] %s is already pending: %s\n", g.Name, h.Provider.RequestURL(g.AccessRequestID))
			if input.Wait {
				return true, res, justActivated, nil
			}
			return false, nil, justActivated, errors.New("access is pending approval")

		case GrantStatusClosed:
			_, _ = color.New(color.FgWhite).Fprintf(os.Stderr, "[CLOSED] %s is closed but was still returned: %s\n. This is most likely due to an error and should be reported.", g.Name, h.Provider.RequestURL(g.AccessRequestID))
			return false, nil, justActivated, errors.New("grant was closed")

		default:
			_, _ = color.New(color.FgWhite).Fprintf(os.Stderr, "[UNSPECIFIED] %s is in an unspecified status: %s\n. This is most likely due to an error and should be reported.", g.Name, h.Provider.RequestURL(g.AccessRequestID))
			return false, nil, justActivated, errors.New("grant was in an unspecified state")
		}
	}

	printDiagnostics(res.Diagnostics)

	return retry, res, justActivated, nil
}

func (h Hook) RetryAccess(ctx context.Context, input NoAccessInput) error {
	if h.Provider == nil {
		return nil
	}

	target := fmt.Sprintf("AWS::Account::%s", input.Profile.AWSConfig.SSOAccountID)
	role := input.Profile.AWSConfig.SSORoleName
	_, err := h.RetryNoEntitlementAccess(ctx, NoEntitlementAccessInput{
		Target:      target,
		Role:        role,
		Reason:      input.Reason,
		Duration:    input.Duration,
		Confirm:     input.Confirm,
		Wait:        input.Wait,
		StartTime:   input.StartTime,
		Attachments: input.Attachments,
	})
	return err
}

func (h Hook) RetryNoEntitlementAccess(ctx context.Context, input NoEntitlementAccessInput) (result *EnsureResponse, err error) {
	req := EnsureRequest{
		Entitlements: []EntitlementInput{
			{
				Target:   input.Target,
				Role:     input.Role,
				Duration: input.Duration,
			},
		},
		Justification: Justification{},
	}

	res, err := h.Provider.Ensure(ctx, &req)
	if err != nil {
		return nil, err
	}

	clio.Debugw("ensure response", "res", debugJSON(res))

	now := time.Now()
	elapsed := now.Sub(input.StartTime).Round(time.Second * 10)

	allGrantsApproved := true
	allGrantsActivated := true
	for _, g := range res.Grants {
		if g.Status == GrantStatusActive {
			continue
		}
		if g.Approved && g.Change == GrantChangeUnspecified && g.ProvisioningStatus != "successful" {
			clio.Infof("Request was approved but failed to activate, you might not have permission to activate. You can try and activate the access using the web console. [%s elapsed]", elapsed)
			printDiagnostics(res.Diagnostics)
		}
		if !g.Approved {
			clio.Infof("Waiting for request to be approved... [%s elapsed]", elapsed)
			allGrantsApproved = false
		}
		if g.ActivatedAt == nil {
			allGrantsActivated = false
		}
	}

	if !allGrantsApproved || !allGrantsActivated {
		return res, errors.New("waiting on all grants to be approved and activated")
	}
	return res, nil
}

func (h Hook) dryRun(ctx context.Context, req *EnsureRequest, jsonOutput bool, confirm bool) (bool, *EnsureResponse, error) {
	req.DryRun = true

	si := spinner.New(spinner.CharSets[14], 100*time.Millisecond)
	si.Suffix = " planning access changes..."
	si.Writer = os.Stderr
	si.Start()

	res, err := h.Provider.Ensure(ctx, req)
	if err != nil {
		si.Stop()
		return false, nil, err
	}

	si.Stop()

	clio.Debugw("Ensure response", "response", debugJSON(res))

	if jsonOutput {
		resJSON, err := json.Marshal(res)
		if err != nil {
			return false, nil, err
		}
		fmt.Println(string(resJSON))
		return false, nil, errors.New("exiting because --output=json was specified: use --output=text to show an interactive prompt, or use --confirm to proceed with the changes")
	}

	var hasChanges bool

	for _, g := range res.Grants {
		exp := ShortDur(g.Duration)

		if g.Change != GrantChangeNone && g.Change != GrantChangeUnspecified {
			hasChanges = true
		}

		switch g.Change {
		case GrantChangeActivated:
			_, _ = color.New(color.BgHiGreen).Fprintf(os.Stderr, "[WILL ACTIVATE]")
			_, _ = color.New(color.FgGreen).Fprintf(os.Stderr, " %s will be activated for %s: %s\n", g.Name, exp, h.Provider.RequestURL(g.AccessRequestID))
			continue

		case GrantChangeExtended:
			extendedTime := ""
			if g.Extension != nil {
				extendedTime = ShortDur(g.Extension.ExtensionDuration)
			}
			_, _ = color.New(color.BgBlue).Printf("[WILL EXTEND]")
			_, _ = color.New(color.FgBlue).Printf(" %s will be extended for another %s: %s\n", g.Name, extendedTime, h.Provider.RequestURL(g.AccessRequestID))
			continue

		case GrantChangeRequested:
			_, _ = color.New(color.BgHiYellow, color.FgBlack).Fprintf(os.Stderr, "[WILL REQUEST]")
			_, _ = color.New(color.FgYellow).Fprintf(os.Stderr, " %s will require approval\n", g.Name)
			continue

		case GrantChangeProvisioningFailed:
			_, _ = color.New(color.FgRed).Fprintf(os.Stderr, "[ERROR] %s will fail provisioning\n", g.Name)
			continue
		}

		switch g.Status {
		case GrantStatusActive:
			if g.ExpiresAt != nil {
				exp = ShortDur(time.Until(*g.ExpiresAt))
			}
			_, _ = color.New(color.FgGreen).Fprintf(os.Stderr, "[ACTIVE] %s is already active for the next %s: %s\n", g.Name, exp, h.Provider.RequestURL(g.AccessRequestID))
			continue
		case GrantStatusPending:
			_, _ = color.New(color.FgWhite).Fprintf(os.Stderr, "[PENDING] %s is already pending: %s\n", g.Name, h.Provider.RequestURL(g.AccessRequestID))
			continue
		case GrantStatusClosed:
			_, _ = color.New(color.FgWhite).Fprintf(os.Stderr, "[CLOSED] %s is closed but was still returned: %s\n. This is most likely due to an error and should be reported.", g.Name, h.Provider.RequestURL(g.AccessRequestID))
			continue
		}

		_, _ = color.New(color.FgWhite).Fprintf(os.Stderr, "[UNSPECIFIED] %s is in an unspecified status: %s\n. This is most likely due to an error and should be reported.", g.Name, h.Provider.RequestURL(g.AccessRequestID))
	}

	printDiagnostics(res.Diagnostics)

	if !hasChanges {
		return false, res, nil
	}

	if !confirm {
		if !IsTerminal(os.Stdin.Fd()) {
			return false, nil, errors.New("detected a noninteractive terminal: to apply the planned changes please re-run with the --confirm flag")
		}

		withStdio := survey.WithStdio(os.Stdin, os.Stderr, os.Stderr)
		confirmPrompt := survey.Confirm{
			Message: "Apply proposed access changes",
		}
		err = survey.AskOne(&confirmPrompt, &confirm, withStdio)
		if err != nil {
			return false, nil, err
		}
	}

	if !confirm {
		return false, nil, errors.New("cancelled operation")
	}

	clio.Info("Attempting to grant access...")
	return confirm, res, nil
}

func IsTerminal(fd uintptr) bool {
	return isatty.IsTerminal(fd) || isatty.IsCygwinTerminal(fd)
}

func ShortDur(d time.Duration) string {
	if d > time.Minute {
		d = d.Round(time.Minute)
	} else {
		d = d.Round(time.Second)
	}

	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = s[:len(s)-2]
	}
	if strings.HasSuffix(s, "h0m") {
		s = s[:len(s)-2]
	}
	return s
}

func printDiagnostics(diags []Diagnostic) {
	for _, d := range diags {
		switch d.Level {
		case "error":
			clio.Errorf("[diagnostic] %s", d.Message)
		case "warning":
			clio.Warnf("[diagnostic] %s", d.Message)
		default:
			clio.Infof("[diagnostic] %s", d.Message)
		}
	}
}

func isUnauthorized(err error) bool {
	if err == nil {
		return false
	}
	var u Unauthorized
	if errors.As(err, &u) {
		return u.IsUnauthorized()
	}
	// Fallback: check for common OAuth2 error strings
	msg := err.Error()
	return strings.Contains(msg, "oauth2: token expired") ||
		strings.Contains(msg, "oauth2: invalid grant") ||
		strings.Contains(msg, `oauth2: "token_expired"`) ||
		strings.Contains(msg, `oauth2: "invalid_grant"`)
}

func debugJSON(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("(marshal error: %v)", err)
	}
	return string(b)
}
