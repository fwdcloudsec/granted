package granted

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stretchr/testify/assert"
)

func TestAssumeWithRetry(t *testing.T) {
	t.Run("succeeds without retrying", func(t *testing.T) {
		calls := 0
		creds, err := assumeWithRetry(context.Background(), time.Second, func(ctx context.Context) (aws.Credentials, error) {
			calls++
			return aws.Credentials{AccessKeyID: "ok"}, nil
		})
		assert.NoError(t, err)
		assert.Equal(t, "ok", creds.AccessKeyID)
		assert.Equal(t, 1, calls)
	})

	t.Run("succeeds after a transient failure", func(t *testing.T) {
		calls := 0
		creds, err := assumeWithRetry(context.Background(), 5*time.Second, func(ctx context.Context) (aws.Credentials, error) {
			calls++
			if calls < 2 {
				return aws.Credentials{}, errors.New("transient failure")
			}
			return aws.Credentials{AccessKeyID: "ok-after-retry"}, nil
		})
		assert.NoError(t, err)
		assert.Equal(t, "ok-after-retry", creds.AccessKeyID)
		assert.GreaterOrEqual(t, calls, 2)
	})

	t.Run("gives up after max duration is exceeded", func(t *testing.T) {
		calls := 0
		_, err := assumeWithRetry(context.Background(), 50*time.Millisecond, func(ctx context.Context) (aws.Credentials, error) {
			calls++
			return aws.Credentials{}, errors.New("permanent failure")
		})
		assert.Error(t, err)
		assert.GreaterOrEqual(t, calls, 1)
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := assumeWithRetry(ctx, time.Second, func(ctx context.Context) (aws.Credentials, error) {
			return aws.Credentials{}, errors.New("should not matter, context is already cancelled")
		})
		assert.Error(t, err)
	})
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	assert.NoError(t, err)
	os.Stdout = w

	fn()

	assert.NoError(t, w.Close())
	os.Stdout = old

	out, err := io.ReadAll(r)
	assert.NoError(t, err)
	return string(out)
}

func TestPrintCredentials(t *testing.T) {
	t.Run("includes expiration when credentials can expire", func(t *testing.T) {
		expires := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		var printErr error
		out := captureStdout(t, func() {
			printErr = printCredentials(aws.Credentials{
				AccessKeyID:     "AKIA...",
				SecretAccessKey: "secret",
				SessionToken:    "token",
				CanExpire:       true,
				Expires:         expires,
			})
		})
		assert.NoError(t, printErr)

		var got awsCredsStdOut
		assert.NoError(t, json.Unmarshal(bytes.TrimSpace([]byte(out)), &got))
		assert.Equal(t, 1, got.Version)
		assert.Equal(t, "AKIA...", got.AccessKeyID)
		assert.Equal(t, "secret", got.SecretAccessKey)
		assert.Equal(t, "token", got.SessionToken)
		assert.Equal(t, expires.Format(time.RFC3339), got.Expiration)
	})

	t.Run("omits expiration when credentials cannot expire", func(t *testing.T) {
		var printErr error
		out := captureStdout(t, func() {
			printErr = printCredentials(aws.Credentials{AccessKeyID: "AKIA...", CanExpire: false})
		})
		assert.NoError(t, printErr)

		var got awsCredsStdOut
		assert.NoError(t, json.Unmarshal(bytes.TrimSpace([]byte(out)), &got))
		assert.Equal(t, "", got.Expiration)
	})
}
