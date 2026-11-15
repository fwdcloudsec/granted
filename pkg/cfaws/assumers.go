package cfaws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"gopkg.in/ini.v1"
)

// NoAccessError is returned if the user does not have access to the
// role they are trying to assume.
type NoAccessError struct {
	// Err is the underlying error from AWS
	Err error
}

func (e NoAccessError) Error() string {
	if e.Err == nil {
		return "no access"
	}

	return fmt.Sprintf("no access: %s", e.Err)
}

// Unwrap the underlying error so that errors.Is and errors.As works
func (e NoAccessError) Unwrap() error {
	return e.Err
}

// Added support for optional pass through args on proxy sso provider
// When using a sso provider adding pass through flags can be achieved by adding the -pass-through or -pt flag
// EG. assume role-a -pt --mode -pt gui (Run the proxy login with a gui rather than in cli. Example taken from aws-azure-login)
type Assumer interface {
	// AssumeTerminal should follow the required process for it implemetation and return aws credentials ready to be exported to the terminal environment
	AssumeTerminal(context.Context, *Profile, ConfigOpts) (aws.Credentials, error)
	// AssumeConsole should follow any console specific credentials processes, this may be the same as AssumeTerminal under the hood
	AssumeConsole(context.Context, *Profile, ConfigOpts) (aws.Credentials, error)
	// A unique key which identifies this assumer e.g AWS-SSO or GOOGLE-AWS-AUTH
	Type() string
	// ProfileMatchesType takes a list of strings which are the lines in an aws config profile and returns true if this profile is the assumers type
	ProfileMatchesType(*ini.Section, config.SharedConfig) bool
}

// List of assumers should be ordered by how they match type
// specific types should be first, generic types like IAM should be last / the (default)
// for sso and aws login profiles, the internal implementation takes precedence over credential processes
var assumers []Assumer = []Assumer{&AwsGimmeAwsCredsAssumer{}, &AwsGoogleAuthAssumer{}, &AwsAzureLoginAssumer{}, &AwsSsoAssumer{}, &AwsLoginAssumer{}, &CredentialProcessAssumer{}, &AwsIamAssumer{}}

// RegisterAssumer allows assumers to be registered when using this library as a package in other projects
// position = -1 will append the assumer
// position to insert assumer
func RegisterAssumer(a Assumer, position int) {
	if position < 0 || position > len(assumers)-1 {
		assumers = append(assumers, a)
	} else {
		newAssumers := append([]Assumer{}, assumers[:position]...)
		newAssumers = append(newAssumers, a)
		assumers = append(newAssumers, assumers[position:]...)
	}
}

func AssumerFromType(t string) Assumer {
	for _, a := range assumers {
		if a.Type() == t {
			return a
		}
	}
	return nil
}
