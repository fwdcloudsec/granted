package granted

import "testing"

func TestResolveDefaultRegion(t *testing.T) {
	tests := []struct {
		name        string
		flagValue   string
		configValue string
		want        string
		wantErr     bool
	}{
		{
			name:        "empty returns empty so no region key is written",
			flagValue:   "",
			configValue: "",
			want:        "",
		},
		{
			name:      "fully-qualified flag value passes through",
			flagValue: "eu-west-1",
			want:      "eu-west-1",
		},
		{
			name:      "shorthand flag value is expanded",
			flagValue: "ew1",
			want:      "eu-west-1",
		},
		{
			name:        "config value is used when flag is empty",
			configValue: "us-east-1",
			want:        "us-east-1",
		},
		{
			name:        "flag value takes precedence over config",
			flagValue:   "ap-southeast-2",
			configValue: "us-east-1",
			want:        "ap-southeast-2",
		},
		{
			name:      "invalid shorthand returns an error",
			flagValue: "x",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveDefaultRegion(tt.flagValue, tt.configValue)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("resolveDefaultRegion(%q, %q) = %q, want %q", tt.flagValue, tt.configValue, got, tt.want)
			}
		})
	}
}
