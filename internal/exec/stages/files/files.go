// Copyright 2015 CoreOS, Inc.
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
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/coreos/ignition/v2/config/v3_7_experimental/types"
	"github.com/coreos/ignition/v2/internal/distro"
	"github.com/coreos/ignition/v2/internal/exec/stages"
	"github.com/coreos/ignition/v2/internal/exec/util"
	"github.com/coreos/ignition/v2/internal/log"
	"github.com/coreos/ignition/v2/internal/resource"
	"github.com/coreos/ignition/v2/internal/state"
)

const (
	name = "files"
)

var (
	ErrFilesystemUndefined = errors.New("the referenced filesystem was not defined")
)

func init() {
	stages.Register(creator{})
}

type creator struct{}

func (creator) Create(logger *log.Logger, root string, f resource.Fetcher, state *state.State) stages.Stage {
	return &stage{
		Util: util.Util{
			DestDir: root,
			Logger:  logger,
			Fetcher: f,
			State:   state,
		},
	}
}

func (creator) Name() string {
	return name
}

type stage struct {
	util.Util
	toRelabel map[string]struct{}
}

func (stage) Name() string {
	return name
}

func (s stage) Apply(config types.Config, ignoreUnsupported bool) error {
	return s.runImpl(config, true, ignoreUnsupported)
}

func (s stage) Run(config types.Config) error {
	return s.runImpl(config, false, false)
}

// runImpl applies the config in four gates:
//
//  1. Plan: pin the config generation, enumerate every target path and
//     snapshot the original identity of anything already present.
//  2. Fetch: retrieve and verify all remote contents into a staging
//     directory; the sysroot is untouched until this succeeds.
//  3. Apply: create directories, files and links, reconcile groups and
//     users, apply identities, write units/dropins and LUKS support
//     files. Each target is verified and individually confirmed in a
//     checkpoint so the stage can resume after process exit or relabel
//     failure.
//  4. Publish: presets, provider output files and the result file are
//     only published once the whole content set is confirmed.
func (s stage) runImpl(config types.Config, isApply bool, applyIgnoreUnsupported bool) error {
	if !isApply {
		// !isApply: SELinux is handled differently in container flows
		if err := s.checkRelabeling(); err != nil {
			return fmt.Errorf("failed to check if SELinux labeling required: %v", err)
		}
	}

	// theoretically could support this, but the main user (CoreOS layering)
	// does not: https://github.com/coreos/rpm-ostree/issues/3435
	if isApply {
		if !applyIgnoreUnsupported && (len(config.Passwd.Users) > 0 || len(config.Passwd.Groups) > 0) {
			return errors.New("cannot apply passwd live")
		}
	}

	// Gate 1: plan and pin the generation.
	p, err := s.initPlan(config, isApply)
	if err != nil {
		return fmt.Errorf("failed to initialize files stage plan: %v", err)
	}
	if isApply {
		// Container flow has no resume state on disk.
		defer p.cleanup()
	}
	if p.cp.Completed {
		// A previous invocation completed but did not get to clean up.
		p.cleanup()
		return nil
	}
	if err := s.buildPlan(config, p); err != nil {
		return fmt.Errorf("failed to build files stage plan: %v", err)
	}

	// Gate 2: fetch and verify everything first.
	if err := s.fetchAll(p); err != nil {
		return fmt.Errorf("failed to fetch staged contents: %v", err)
	}

	// Gate 3a: directories, files, links.
	if err := s.applyTargets(p, phaseStorage); err != nil {
		return fmt.Errorf("failed to create files: %v", err)
	}

	if !isApply {
		// Gate 3b: groups and users (and passwd relabel marks).
		if err := s.applyPasswd(config, p); err != nil {
			return fmt.Errorf("failed to create users/groups: %v", err)
		}
	}

	// Gate 3c: ownership and mode now that referenced users exist.
	if err := s.applyIdentities(p, phaseStorage); err != nil {
		return fmt.Errorf("failed to set file identities: %v", err)
	}

	if !isApply {
		// Gate 3d: home permissions and authorized keys.
		if err := s.finalizeUsers(config, p); err != nil {
			return err
		}
	}

	// Gate 3e: units, dropins and mask/unmask.
	if err := s.applyUnits(p); err != nil {
		return fmt.Errorf("failed to create units: %v", err)
	}

	if !isApply {
		// Gate 3f: crypttab entries and LUKS/CEX key files.
		if err := s.applyLuks(config, p); err != nil {
			return err
		}

		// Relabel the whole content set before publishing anything.
		if !p.cp.RelabelContentDone {
			s.replayTargetRelabels(p)
			if err := s.relabelFiles(); err != nil {
				return fmt.Errorf("failed to handle relabeling: %v", err)
			}
			p.cp.RelabelContentDone = true
			if err := p.save(); err != nil {
				return err
			}
		}
	}

	// Gate 4: publication, only after the content set is confirmed.
	if !p.cp.PresetsDone {
		if err := s.publishPresets(p); err != nil {
			return fmt.Errorf("failed to publish systemd presets: %v", err)
		}
	}

	if !isApply {
		if err := s.publishProvider(p); err != nil {
			return fmt.Errorf("creating provider state files: %v", err)
		}
		if err := s.publishResult(p); err != nil {
			return fmt.Errorf("creating result file: %v", err)
		}

		if !p.cp.RelabelPublishDone {
			// Confirmed publication targets and the preset file must be
			// covered even when publication was skipped on resume.
			s.replayTargetRelabels(p)
			if len(p.cp.Presets) > 0 {
				if presetPath, err := s.JoinPath(util.PresetPath); err != nil {
					return err
				} else if err := s.relabelPath(presetPath); err != nil {
					return err
				}
			}
			if err := s.relabelFiles(); err != nil {
				return fmt.Errorf("failed to relabel published files: %v", err)
			}
			p.cp.RelabelPublishDone = true
			if err := p.save(); err != nil {
				return err
			}
		}
	}

	p.cp.Completed = true
	if err := p.save(); err != nil {
		return err
	}
	p.cleanup()
	return nil
}

// applyLuks applies the planned crypttab and keyfile targets and then
// clears the persisted key material from state.
func (s *stage) applyLuks(config types.Config, p *filesPlan) error {
	if err := s.applyTargets(p, phaseLuks); err != nil {
		return fmt.Errorf("adding luks related files: %v", err)
	}
	if err := s.applyIdentities(p, phaseLuks); err != nil {
		return fmt.Errorf("setting luks file permissions: %v", err)
	}
	// delete the persisted keyfiles from state so that the keyfiles are
	// stored on only the root device which can be encrypted
	if len(config.Storage.Luks) > 0 {
		s.State.LuksPersistKeyFiles = nil
	}
	return nil
}

// publishProvider applies provider-generated output files.
func (s *stage) publishProvider(p *filesPlan) error {
	if p.cp.ProviderDone {
		return nil
	}
	// The result file is appended to this phase later; applyTargets only
	// touches targets that currently exist.
	if err := s.applyTargets(p, phasePublish); err != nil {
		return err
	}
	if err := s.applyIdentities(p, phasePublish); err != nil {
		return err
	}
	p.cp.ProviderDone = true
	return p.save()
}

// publishResult renders and installs the run result file.
func (s *stage) publishResult(p *filesPlan) error {
	if p.cp.ResultDone {
		return nil
	}
	if distro.ResultFilePath() == "" {
		p.cp.ResultDone = true
		return p.save()
	}

	data, err := s.buildResultData()
	if err != nil {
		return err
	}
	path, err := s.JoinPath(distro.ResultFilePath())
	if err != nil {
		return fmt.Errorf("building result file path: %v", err)
	}
	t, err := s.stagePublishFile(p, path, data, 0600)
	if err != nil {
		return err
	}
	if err := s.applyTarget(p, t); err != nil {
		return err
	}
	if err := s.applyIdentities(p, phasePublish); err != nil {
		return err
	}
	p.cp.ResultDone = true
	return p.save()
}

// checkRelabeling determines whether relabeling is supported/requested so that
// we only collect filenames if we need to.
func (s *stage) checkRelabeling() error {
	if !distro.SelinuxRelabel() {
		s.Debug("compiled without relabeling support, skipping")
		return nil
	}

	// initialize to non-nil (whereas a nil map means not to append, even
	// though they're functionally equivalent)
	s.toRelabel = make(map[string]struct{})
	return nil
}

// relabeling returns true if we are relabeling, false otherwise.
func (s *stage) relabeling() bool {
	return s.toRelabel != nil
}

// relabel adds one or more paths to the list of paths that need relabeling.
func (s *stage) relabel(paths ...string) {
	if s.toRelabel != nil {
		for _, path := range paths {
			s.toRelabel[filepath.Join(s.DestDir, path)] = struct{}{}
		}
	}
}

// relabelFiles relabels all the files that were marked for relabeling using
// the libselinux APIs.
func (s *stage) relabelFiles() error {
	if len(s.toRelabel) == 0 {
		return nil
	}

	// We could go further here and use the `setfscreatecon` API so that we
	// atomically create the files from the start with the right label, but (1)
	// atomicity isn't really necessary here since there is not even a policy
	// loaded and hence no MAC enforced, and (2) we'd still need after-the-fact
	// labeling for files created by processes we call out to, like `useradd`.

	keys := make([]string, 0, len(s.toRelabel))
	for key := range s.toRelabel {
		// Filter out non-existent entries; some of the code that mark files for
		// relabeling may not actually end up creating those files in the end.
		if _, err := os.Stat(key); err == nil {
			keys = append(keys, key)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}

	if len(keys) == 0 {
		return nil
	}

	return s.RelabelFiles(keys)
}
