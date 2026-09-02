package cfaws

import (
	"testing"
)

func TestValidateCredentialProcess(t *testing.T) {
	tests := []struct {
		name        string
		arg         string
		profileName string
		wantErr     string
	}{
		{
			name:        "valid argument with correct profile name",
			arg:         "  granted credential-process   --profile develop",
			profileName: "develop",
		},
		{
			name:        "valid argument with incorrect profile name",
			arg:         "granted credential-process --profile abc",
			profileName: "develop",
			wantErr:     "unmatched profile names. The profile name 'abc' provided to 'granted credential-process' does not match AWS profile name 'develop'",
		},
		{
			name:        "invalid argument",
			arg:         "aws-sso-util --profile abc",
			profileName: "apple",
			wantErr:     "unable to parse 'credential_process'. Looks like your credential_process isn't configured correctly. \n You need to add 'granted credential-process --profile <profile-name>'",
		},
		{
			name:        "valid argument using dgranted bare command",
			arg:         "dgranted credential-process --profile develop",
			profileName: "develop",
		},
		{
			name:        "valid argument with relative path",
			arg:         "./granted credential-process --profile develop",
			profileName: "develop",
		},
		{
			name:        "valid argument with relative path in subdirectory",
			arg:         "bin/dgranted credential-process --profile develop",
			profileName: "develop",
		},
		{
			name:        "valid argument with absolute unix path",
			arg:         "/home/user/.local/bin/granted credential-process --profile develop",
			profileName: "develop",
		},
		{
			name:        "valid argument with absolute unix path and profile containing a slash",
			arg:         "/home/user/.local/bin/granted credential-process --profile my-account/MyRole",
			profileName: "my-account/MyRole",
		},
		{
			name:        "valid argument with absolute unix path to dgranted",
			arg:         "/home/user/.local/bin/dgranted credential-process --profile develop",
			profileName: "develop",
		},
		{
			name:        "valid argument with windows path and .exe suffix",
			arg:         `C:\Users\foo\bin\granted.exe credential-process --profile develop`,
			profileName: "develop",
		},
		{
			name:        "valid argument with windows path and .exe suffix to dgranted",
			arg:         `C:\Users\foo\bin\dgranted.exe credential-process --profile develop`,
			profileName: "develop",
		},
		{
			name:        "valid argument with bare .exe suffix",
			arg:         "granted.exe credential-process --profile develop",
			profileName: "develop",
		},
		{
			name:        "full path with mismatched profile name still detected",
			arg:         "/home/user/.local/bin/granted credential-process --profile abc",
			profileName: "develop",
			wantErr:     "unmatched profile names. The profile name 'abc' provided to 'granted credential-process' does not match AWS profile name 'develop'",
		},
		{
			name:        "rejects an unrelated binary invoked via an absolute path",
			arg:         "/usr/local/bin/aws-vault credential-process --profile develop",
			profileName: "develop",
			wantErr:     "unable to parse 'credential_process'. Looks like your credential_process isn't configured correctly. \n You need to add 'granted credential-process --profile <profile-name>'",
		},
		{
			name:        "rejects a binary that merely starts with 'granted'",
			arg:         "/usr/local/bin/granted-wrapper credential-process --profile develop",
			profileName: "develop",
			wantErr:     "unable to parse 'credential_process'. Looks like your credential_process isn't configured correctly. \n You need to add 'granted credential-process --profile <profile-name>'",
		},
		{
			name:        "rejects a bare command that merely starts with 'granted'",
			arg:         "grantedx credential-process --profile develop",
			profileName: "develop",
			wantErr:     "unable to parse 'credential_process'. Looks like your credential_process isn't configured correctly. \n You need to add 'granted credential-process --profile <profile-name>'",
		},
		{
			name:        "missing profile name",
			arg:         "granted credential-process",
			profileName: "develop",
			wantErr:     "unable to parse 'credential_process'. Looks like your credential_process isn't configured correctly. \n You need to add 'granted credential-process --profile <profile-name>'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			err := validateCredentialProcess(tt.arg, tt.profileName)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error %q, got nil", tt.wantErr)
			}
			if err.Error() != tt.wantErr {
				t.Fatal(err)
			}
		})
	}
}
