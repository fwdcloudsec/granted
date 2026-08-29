# Granted Integration Testing

This directory contains integration tests for the Granted CLI tool, focusing on the `assume` command with mocked AWS APIs.

## Quick Start

```bash
# Run E2E tests locally
GRANTED_E2E_TESTING=true go test ./pkg/integration_testing/...

# Run with pre-built binary
GRANTED_E2E_TESTING=true GRANTED_BINARY_PATH=/path/to/dgranted go test ./pkg/integration_testing/... -run TestAssumeCommandE2E

# Use the test script
GRANTED_E2E_TESTING=true ./pkg/integration_testing/test_e2e.sh
```

## Overview

The integration test suite validates the core functionality of Granted's `assume` command by:
- Building (or using pre-built) Granted binary
- Creating isolated test environments
- Running the actual CLI command
- Verifying credential output format
- Using mock AWS servers to avoid external dependencies

## Test Structure

- **`assume_e2e_test.go`** - End-to-end test for assume command
- **`simple_mock_server.go`** - Lightweight AWS API mock server
- **`simple_sso_test.go`** - Basic SSO workflow tests
- **`sso_test.go`** - SSO profile and token tests
- **`test_e2e.sh`** - Helper script to run E2E tests
- **`E2E_TESTING.md`** - Detailed E2E testing documentation

## Environment Variables

- `GRANTED_E2E_TESTING=true` - **Required** to enable E2E tests
- `GRANTED_BINARY_PATH` - Path to pre-built binary (optional, builds if not provided)

## CI Integration

Tests run automatically in GitHub Actions when:
1. Code is pushed or PR is created
2. The `integration-test` job downloads pre-built binaries
3. Tests execute with `GRANTED_E2E_TESTING=true`

## Mock Server

The test suite includes a mock AWS server that simulates:
- SSO GetRoleCredentials API
- SSO ListAccounts API
- SSO ListAccountRoles API
- OIDC CreateToken API

This allows testing without real AWS credentials or network access.

## Extending Tests

To add new test scenarios:
1. Add profiles to the test AWS config
2. Create test functions following existing patterns  
3. Use mock server for SSO/OIDC flows
4. Verify expected credential output format

For detailed documentation, see [E2E_TESTING.md](E2E_TESTING.md).