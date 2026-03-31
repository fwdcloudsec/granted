package rds

type getLocalPortInput struct {
	// OverrideFlag is set by the user using the --port flag
	OverrideFlag int
	// DefaultFromServer is the port number specified by admins in the Terraform provider
	DefaultFromServer int
	// Fallback is the port to default to if OverrideFlag and DefaultFromServer are not set
	Fallback int
}

// getLocalPort returns the port number to use for the local port
//
// Common Fate allows admins to set default ports in the Terraform provider and
// users to override them with the --port flag when running granted rds proxy --port <port>
//
// The order of priorities is:
// 1. OverrideFlag
// 2. DefaultFromServer
// 3. Fallback
//
// You should set Fallback to 5432 for PostgreSQL and 3306 for MySQL
func getLocalPort(input getLocalPortInput) int {
	if input.OverrideFlag != 0 {
		return input.OverrideFlag
	}
	if input.DefaultFromServer != 0 {
		return input.DefaultFromServer
	}
	return input.Fallback
}
