package rds

import "testing"

func Test_getLocalPort(t *testing.T) {
	type args struct {
		input getLocalPortInput
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		// TODO: Add test cases.
		{
			name: "OverridePortTakesPriority",
			args: args{
				input: getLocalPortInput{
					OverrideFlag:      5000,
					DefaultFromServer: 8080,
					Fallback:          5432,
				},
			},
			want: 5000,
		},
		{
			name: "DefaultFromServerTakesPriority",
			args: args{
				input: getLocalPortInput{
					OverrideFlag:      0,
					DefaultFromServer: 8080,
					Fallback:          5432,
				},
			},
			want: 8080,
		},
		{
			name: "FallbackTakesPriority",
			args: args{
				input: getLocalPortInput{
					OverrideFlag:      0,
					DefaultFromServer: 0,
					Fallback:          5432,
				},
			},
			want: 5432,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getLocalPort(tt.args.input); got != tt.want {
				t.Errorf("getLocalPort() = %v, want %v", got, tt.want)
			}
		})
	}
}
