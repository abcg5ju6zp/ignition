// Copyright 2018 CoreOS, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package files

import (
	"fmt"
	"path/filepath"

	"github.com/coreos/ignition/v2/config/util"
	"github.com/coreos/ignition/v2/config/v3_7_experimental/types"
)

func (s *stage) expandGlobList(globs ...string) ([]string, error) {
	ret := []string{}
	for _, glob := range globs {
		matches, err := filepath.Glob(filepath.Join(s.DestDir, glob))
		if err != nil {
			return nil, err
		}
		for _, match := range matches {
			rel, err := filepath.Rel(s.DestDir, match)
			if err != nil {
				return nil, err
			}
			ret = append(ret, filepath.Join("/", rel))
		}
	}
	return ret, nil
}

// applyPasswd reconciles groups and users (in that order) and marks
// passwd-related paths for relabeling.  Home-directory permissions and
// SSH keys are finalized separately once file identities are applied.
func (s *stage) applyPasswd(config types.Config, p *filesPlan) error {
	if err := s.reconcileGroups(config, p); err != nil {
		return fmt.Errorf("failed to configure groups: %v", err)
	}
	if err := s.reconcileUsers(config, p); err != nil {
		return fmt.Errorf("failed to configure users: %v", err)
	}

	// to be safe, just blanket mark all passwd-related files rather than
	// trying to make it more granular based on which executables we ran
	if len(config.Passwd.Groups) != 0 || len(config.Passwd.Users) != 0 {
		// Expand the globs now so tools that do not do glob expansion can parse them.
		// Do this before handling files/links/dirs so we don't accidently expand paths
		// for those if the user specifies a path which includes globbing characters.
		deglobbed, err := s.expandGlobList("/etc/passwd*",
			"/etc/group*",
			"/etc/shadow*",
			"/etc/gshadow*",
			"/etc/subuid*",
			"/etc/subgid*")
		if err != nil {
			return err
		}

		s.relabel(deglobbed...)
		s.relabel("/etc/.pwd.lock")
		for _, user := range config.Passwd.Users {
			if util.IsTrue(user.NoCreateHome) {
				continue
			}
			if util.IsFalse(user.ShouldExist) {
				continue
			}
			homedir, err := s.GetUserHomeDir(user)
			if err != nil {
				return err
			}

			// Resolve intermediate symlinks in the homedir path.
			// This is relevant on OSTree-based platforms, where
			// /home is a symlink to var/home.
			resolvedPath, err := s.JoinPath(homedir)
			if err != nil {
				return err
			}
			unprefixed := resolvedPath[len(s.DestDir):]

			// Check if the homedir is actually a symlink, and make sure we
			// relabel the target instead in that case. This is relevant on
			// OSTree-based platforms, where /root is a link to /var/roothome.
			if target, err := s.ResolveSymlink(unprefixed); err != nil {
				return err
			} else if target != "" {
				// note we don't relabel the symlink itself; we assume it's
				// already properly labeled
				s.relabel(target)
			} else {
				s.relabel(unprefixed)
			}
		}
	}

	return nil
}
