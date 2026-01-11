package gitregistry

import (
	"os"

	"github.com/fwdcloudsec/granted/pkg/git"
)

// pull ensures the remote git repo is cloned and the latest changes are pulled.
func (r Registry) pull() error {
	if _, err := os.Stat(r.clonedTo); err != nil {
		// folder doesn't exist yet, so clone the repo and return early.
		return git.CloneWithRef(r.opts.URL, r.clonedTo, r.opts.Ref)
	}

	// if we get here, the folder exists, so pull any changes.
	err := git.PullRef(r.clonedTo, r.opts.Ref, false)
	if err != nil {
		return err
	}

	return nil
}
