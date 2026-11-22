package assume

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/fwdcloudsec/granted/pkg/cfaws"
	"gopkg.in/ini.v1"
)

func TestProfileSelfRefreshes(t *testing.T) {
	credProcess := ini.Empty().Section("profile cp")
	credProcess.Key("credential_process").SetValue("granted credential-process --profile cp")
	plain := ini.Empty().Section("profile plain")
	managed := ini.Empty().Section("profile managed")
	managed.Key(cfaws.GrantedLoginSessionKey).SetValue("arn:aws:iam::123456789012:user/alice")
	managedCP := ini.Empty().Section("profile managed-cp")
	managedCP.Key(cfaws.GrantedLoginSessionKey).SetValue("arn:aws:iam::123456789012:user/alice")
	managedCP.Key("credential_process").SetValue("granted credential-process --profile=managed-cp")

	tests := []struct {
		name    string
		profile *cfaws.Profile
		want    bool
	}{
		{"credential_process", &cfaws.Profile{RawConfig: credProcess, ProfileType: "AWS_CREDENTIAL_PROCESS"}, true},
		{"root aws login profile", &cfaws.Profile{RawConfig: plain, ProfileType: cfaws.ProfileTypeAWSLogin}, true},
		{"managed login profile with credential_process", &cfaws.Profile{RawConfig: managedCP, ProfileType: cfaws.ProfileTypeAWSLogin}, true},
		{"managed login profile without credential_process exports keys", &cfaws.Profile{RawConfig: managed, ProfileType: cfaws.ProfileTypeAWSLogin}, false},
		{"role chained from managed login profile", &cfaws.Profile{RawConfig: plain, ProfileType: cfaws.ProfileTypeAWSLogin, AWSConfig: config.SharedConfig{RoleARN: "arn:aws:iam::123456789012:role/dev"}}, false},
		{"role chained from aws login profile", &cfaws.Profile{RawConfig: plain, ProfileType: cfaws.ProfileTypeAWSLogin, AWSConfig: config.SharedConfig{RoleARN: "arn:aws:iam::123456789012:role/dev"}}, false},
		{"iam profile", &cfaws.Profile{RawConfig: plain, ProfileType: "AWS_IAM"}, false},
		{"sso profile", &cfaws.Profile{RawConfig: plain, ProfileType: "AWS_SSO"}, false},
		{"nil raw config does not panic", &cfaws.Profile{ProfileType: "AWS_IAM"}, false},
		{"nil raw config aws login", &cfaws.Profile{ProfileType: cfaws.ProfileTypeAWSLogin}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := profileSelfRefreshes(tt.profile); got != tt.want {
				t.Errorf("profileSelfRefreshes() = %v, want %v", got, tt.want)
			}
		})
	}
}
