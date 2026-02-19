# End-to-End Integration Testing for Granted Assume Command

This directory contains integration tests that verify the `assume` command works correctly in a realistic environment with mocked AWS APIs.

## Architecture

The integration test suite consists of:

1. **Mock AWS Server** (`assume_e2e_test.go`)
   - Simulates AWS SSO, OIDC, and STS endpoints
   - Returns mock credentials without requiring network access
   - Tracks access for verification

2. **E2E Test** (`TestAssumeCommandE2E`)
   - Uses pre-built binary from CI or builds one locally
   - Creates isolated test environment (temp directories)
   - Runs the assume command with real AWS config files
   - Verifies credential output format

## Running the Tests

### Locally

```bash
# Run the E2E test (builds binary if needed)
GRANTED_E2E_TESTING=true go test -v -run TestAssumeCommandE2E ./pkg/integration_testing/...

# Use with pre-built binary
GRANTED_E2E_TESTING=true GRANTED_BINARY_PATH=/path/to/dgranted go test -v -run TestAssumeCommandE2E ./pkg/integration_testing/...

# Or use the test script (checks for GRANTED_E2E_TESTING automatically)
GRANTED_E2E_TESTING=true ./pkg/integration_testing/test_e2e.sh
```

### In CI (GitHub Actions)

The test runs automatically on push/PR via `.github/workflows/test.yml` in the `integration-test` job:
- Uses binaries built in the `test` job
- Downloads the Linux binaries artifact
- Sets `GRANTED_BINARY_PATH` environment variable
- Runs the integration test suite

## Test Flow

1. **Binary Setup**
   - CI: Uses pre-built binary from artifacts
   - Local: Builds binary if `GRANTED_BINARY_PATH` not set

2. **Environment Setup**
   - Creates temporary home directory
   - Sets up AWS config with test IAM profile
   - Configures granted settings
   - Starts mock AWS server

3. **Execution Phase**
   - Runs `dgranted test-iam` command
   - Captures stdout/stderr
   - Mock server handles any AWS API calls

4. **Verification Phase**
   - Checks output contains "GrantedAssume" marker
   - Verifies credential format
   - Validates access key, secret key presence
   - Ensures session token is "None" for IAM profiles

## Environment Variables

The test uses these environment variables:

- `GRANTED_E2E_TESTING=true`: **Required** to enable E2E tests
- `GRANTED_BINARY_PATH`: Path to pre-built binary (optional)
- `HOME`: Temp directory for test isolation
- `AWS_CONFIG_FILE`: Points to test AWS config
- `GRANTED_STATE_DIR`: Test granted config directory
- `GRANTED_QUIET=true`: Suppresses info messages
- `FORCE_NO_ALIAS=true`: Skips shell alias setup
- `FORCE_ASSUME_CLI=true`: Forces assume mode

## Key Components

### Test AWS Config

```ini
[profile test-iam]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region = us-east-1
```

### Expected Output Format

```
GrantedAssume AKIAIOSFODNN7EXAMPLE <secret> None test-iam us-east-1 ...
```

## Extending the Tests

To add new test scenarios:

1. Add new profiles to the AWS config
2. Create new test functions following the pattern
3. Use mock server for SSO/OIDC flows
4. Verify expected output format

## Troubleshooting

- If build fails: Check Go version and CGO settings
- If assume fails: Check environment variables
- If output unexpected: Enable debug logging by removing `GRANTED_QUIET`
- In CI: Check that binary artifacts are properly downloaded

## Benefits

- **Realistic Testing**: Uses actual binary, not unit tests
- **CI/CD Integration**: Runs in main GitHub Actions workflow
- **Build Efficiency**: Reuses pre-built binaries in CI
- **No External Dependencies**: Mock server avoids AWS calls
- **Fast Execution**: No network or auth delays
- **Isolated**: Temp directories prevent conflicts