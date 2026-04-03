package proxy

import (
	"context"
	"errors"
	"time"

	"connectrpc.com/connect"
	"github.com/common-fate/clio"
	"github.com/fwdcloudsec/granted/pkg/hook/accessrequesthook"
	"github.com/common-fate/sdk/config"
	accessv1alpha1 "github.com/common-fate/sdk/gen/commonfate/access/v1alpha1"
	"github.com/common-fate/sdk/service/access/grants"
	sethRetry "github.com/sethvargo/go-retry"
	"google.golang.org/protobuf/types/known/durationpb"
)

func durationOrDefault(duration time.Duration) *durationpb.Duration {
	var out *durationpb.Duration
	if duration != 0 {
		out = durationpb.New(duration)
	}
	return out
}

type EnsureAccessInput[T any] struct {
	Target               string
	Role                 string
	Duration             time.Duration
	Reason               string
	Attachments          []string
	Confirm              bool
	Wait                 bool
	PromptForEntitlement func(ctx context.Context, cfg *config.Context) (*accessv1alpha1.Entitlement, error)
	GetGrantOutput       func(msg *accessv1alpha1.GetGrantOutputResponse) (T, error)
}
type EnsureAccessOutput[T any] struct {
	GrantOutput T
	Grant       *accessv1alpha1.Grant
}

// ensureAccess checks for an existing grant or creates a new one if it does not exist
func EnsureAccess[T any](ctx context.Context, cfg *config.Context, input EnsureAccessInput[T]) (*EnsureAccessOutput[T], error) {

	accessRequestInput := accessrequesthook.NoEntitlementAccessInput{
		Target:      input.Target,
		Role:        input.Role,
		Reason:      input.Reason,
		Attachments: input.Attachments,
		Duration:    durationOrDefault(input.Duration),
		Confirm:     input.Confirm,
		Wait:        input.Wait,
		StartTime:   time.Now(),
	}

	if accessRequestInput.Target == "" && accessRequestInput.Role == "" {
		selectedEntitlement, err := input.PromptForEntitlement(ctx, cfg)
		if err != nil {
			return nil, err
		}
		clio.Debugw("selected target and role manually", "selectedEntitlement", selectedEntitlement)
		accessRequestInput.Target = selectedEntitlement.Target.Eid.Display()
		accessRequestInput.Role = selectedEntitlement.Role.Eid.Display()
	}

	hook := accessrequesthook.Hook{}
	retry, result, _, err := hook.NoEntitlementAccess(ctx, cfg, accessRequestInput)
	if err != nil {
		return nil, err
	}

	retryDuration := time.Minute * 1
	if input.Wait {
		//if wait is specified, increase the timeout to 15 minutes.
		retryDuration = time.Minute * 15
	}

	if retry {
		// reset the start time for the timer (otherwise it shows 2s, 7s, 12s etc)
		accessRequestInput.StartTime = time.Now()

		b := sethRetry.NewConstant(5 * time.Second)
		b = sethRetry.WithMaxDuration(retryDuration, b)
		err = sethRetry.Do(ctx, b, func(ctx context.Context) (err error) {

			//also proactively check if request has been approved and attempt to activate
			result, err = hook.RetryNoEntitlementAccess(ctx, cfg, accessRequestInput)
			if err != nil {

				return sethRetry.RetryableError(err)
			}

			return nil
		})
		if err != nil {
			return nil, err
		}

	}

	if result == nil || len(result.Grants) == 0 {
		return nil, errors.New("could not load grant from Common Fate")
	}

	grant := result.Grants[0]

	grantsClient := grants.NewFromConfig(cfg)

	grantOutput, err := grantsClient.GetGrantOutput(ctx, connect.NewRequest(&accessv1alpha1.GetGrantOutputRequest{
		Id: grant.Grant.Id,
	}))
	if err != nil {
		return nil, err
	}

	clio.Debugw("found grant output", "output", grantOutput)

	grantOutputFromRes, err := input.GetGrantOutput(grantOutput.Msg)
	if err != nil {
		return nil, err
	}

	return &EnsureAccessOutput[T]{
		GrantOutput: grantOutputFromRes,
		Grant:       grant.Grant,
	}, nil
}
