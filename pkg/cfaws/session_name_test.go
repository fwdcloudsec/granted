package cfaws

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/stretchr/testify/assert"
)

// sessionName returns a unique session identifier for the aws console
// this ensures that user activity can be easily audited per session
func TestSessionName(t *testing.T) {
	// getfederationtoken fails if name is longer than 32 characters long
	name := sessionName()
	assert.LessOrEqual(t, len(name), 32)
}

func TestFindRoleSessionNameInParents(t *testing.T) {
	// Test case: No parent profiles
	profile := &Profile{
		AWSConfig: config.SharedConfig{RoleSessionName: ""},
		Parents:   nil,
	}
	assert.Equal(t, "", findRoleSessionNameInParents(profile))

	// Test case: Parent profile with RoleSessionName
	parentProfile := &Profile{
		AWSConfig: config.SharedConfig{RoleSessionName: "parent-session"},
		Parents:   nil,
	}
	profile.Parents = []*Profile{parentProfile}
	assert.Equal(t, "parent-session", findRoleSessionNameInParents(profile))

	// Test case: Multiple parent profiles
	grandParentProfile := &Profile{
		AWSConfig: config.SharedConfig{RoleSessionName: "grandparent-session"},
		Parents:   nil,
	}
	parentProfile.Parents = []*Profile{grandParentProfile}
	assert.Equal(t, "parent-session", findRoleSessionNameInParents(profile))
}

func TestGetRoleSessionNameFromProfile(t *testing.T) {
	// Test case: Profile with RoleSessionName
	profile := &Profile{
		AWSConfig: config.SharedConfig{RoleSessionName: "profile-session"},
		Parents:   nil,
	}
	assert.Equal(t, "profile-session", getRoleSessionNameFromProfile(profile))

	// Test case: Parent profile with RoleSessionName
	parentProfile := &Profile{
		AWSConfig: config.SharedConfig{RoleSessionName: "parent-session"},
		Parents:   nil,
	}
	profile = &Profile{
		AWSConfig: config.SharedConfig{RoleSessionName: ""},
		Parents:   []*Profile{parentProfile},
	}
	assert.Equal(t, "parent-session", getRoleSessionNameFromProfile(profile))

	// Test case: No RoleSessionName in profile or parents
	profile = &Profile{
		AWSConfig: config.SharedConfig{RoleSessionName: ""},
		Parents:   nil,
	}
	name := getRoleSessionNameFromProfile(profile)
	assert.NotEmpty(t, name)
	assert.Contains(t, name, "gntd-")
}
