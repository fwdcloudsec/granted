package launcher

import (
	"reflect"
	"testing"

	"github.com/fwdcloudsec/granted/pkg/config"
)

func TestCustom_LaunchCommand(t *testing.T) {
	type fields struct {
		Command      string
		ForkProcess  bool
		TemplateArgs map[string]string
	}
	type args struct {
		url     string
		profile string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "ok",
			fields: fields{
				Command: "/usr/bin/firefox --url {{.URL}} --profile {{.Profile}}",
			},
			args: args{
				url:     "https://commonfate.io",
				profile: "example",
			},
			want: []string{"/usr/bin/firefox", "--url", "https://commonfate.io", "--profile", "example"},
		},
		{
			name: "empty_profile",
			fields: fields{
				Command: "/usr/bin/firefox --url {{.URL}} --profile {{.Profile}}",
			},
			args: args{
				url:     "https://commonfate.io",
				profile: "",
			},
			want: []string{"/usr/bin/firefox", "--url", "https://commonfate.io", "--profile", ""},
		},
		{
			name: "with_args",
			fields: fields{
				Command: "{{.Args.Foo}}",
				TemplateArgs: map[string]string{
					"Foo": "Bar",
				},
			},
			want: []string{"Bar"},
		},
		{
			name: "invalid_template",
			fields: fields{
				Command: "{{.Invalid}}",
			},
			wantErr: true,
		},
		{
			name: "error_if_no_command_specified",
			fields: fields{
				Command: "",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := Custom{
				Command:      tt.fields.Command,
				ForkProcess:  tt.fields.ForkProcess,
				TemplateArgs: tt.fields.TemplateArgs,
			}
			got, err := l.LaunchCommand(tt.args.url, tt.args.profile)
			if (err != nil) != tt.wantErr {
				t.Errorf("Custom.LaunchCommand() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Custom.LaunchCommand() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCustom_UseForkProcess(t *testing.T) {
	type fields struct {
		Command      string
		ForkProcess  bool
		TemplateArgs map[string]string
	}
	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{
			name: "ok",
			fields: fields{
				ForkProcess: true,
			},
			want: true,
		},
		{
			name: "false",
			fields: fields{
				ForkProcess: false,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := Custom{
				Command:      tt.fields.Command,
				ForkProcess:  tt.fields.ForkProcess,
				TemplateArgs: tt.fields.TemplateArgs,
			}
			if got := l.UseForkProcess(); got != tt.want {
				t.Errorf("Custom.UseForkProcess() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCustomFromLaunchTemplate(t *testing.T) {
	type args struct {
		lt   *config.BrowserLaunchTemplate
		args []string
	}
	tests := []struct {
		name    string
		args    args
		want    Custom
		wantErr bool
	}{
		{
			name: "ok",
			args: args{
				lt: &config.BrowserLaunchTemplate{
					UseForkProcess: true,
					Command:        "foo",
				},
				args: []string{"foo=bar"},
			},
			want: Custom{
				Command:     "foo",
				ForkProcess: true,
				TemplateArgs: map[string]string{
					"foo": "bar",
				},
			},
		},
		{
			name: "ok_with_empty_args",
			args: args{
				lt: &config.BrowserLaunchTemplate{
					UseForkProcess: true,
					Command:        "foo",
				},
			},
			want: Custom{
				Command:      "foo",
				ForkProcess:  true,
				TemplateArgs: map[string]string{},
			},
		},
		{
			name: "invalid_args",
			args: args{
				lt: &config.BrowserLaunchTemplate{
					UseForkProcess: true,
					Command:        "foo",
				},
				args: []string{"invalid"},
			},
			wantErr: true,
		},
		{
			name: "ok",
			args: args{
				lt: &config.BrowserLaunchTemplate{
					UseForkProcess: true,
					Command:        "foo",
				},
				args: []string{"foo=bar"},
			},
			want: Custom{
				Command:     "foo",
				ForkProcess: true,
				TemplateArgs: map[string]string{
					"foo": "bar",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CustomFromLaunchTemplate(tt.args.lt, tt.args.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("CustomFromLaunchTemplate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CustomFromLaunchTemplate() = %v, want %v", got, tt.want)
			}
		})
	}
}
