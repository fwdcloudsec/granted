package cfaws

import "github.com/segmentio/ksuid"

// sessionName returns a unique session identifier for the aws console
// this ensures that user activity can be easily audited per session
// this uses the convenient ksuid library for generating unique IDs
func sessionName() string {
	// using the acronym gntd to ensure the id is not longer than 32 chars
	return "gntd-" + ksuid.New().String()
}

// findRoleSessionNameInParents recursively searches parent profiles for a RoleSessionName.
func findRoleSessionNameInParents(profile *Profile) string {
	if profile == nil {
		return ""
	}
	if profile.AWSConfig.RoleSessionName != "" {
		return profile.AWSConfig.RoleSessionName
	}
	if len(profile.Parents) > 0 {
		return findRoleSessionNameInParents(profile.Parents[0])
	}
	return ""
}

// getRoleSessionNameFromProfile determines the RoleSessionName for a profile.
// It checks the profile itself, then recursively checks parent profiles, and finally falls back to a generated session name.
func getRoleSessionNameFromProfile(profile *Profile) string {
	if profile.AWSConfig.RoleSessionName != "" {
		return profile.AWSConfig.RoleSessionName
	}
	parentRoleSessionName := findRoleSessionNameInParents(profile)
	if parentRoleSessionName != "" {
		return parentRoleSessionName
	}
	return sessionName()
}
