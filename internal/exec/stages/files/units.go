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
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/coreos/ignition/v2/config/shared/errors"
	"github.com/coreos/ignition/v2/config/v3_7_experimental/types"
	"github.com/coreos/ignition/v2/internal/distro"
	"github.com/coreos/ignition/v2/internal/exec/util"
	"github.com/coreos/ignition/v2/internal/systemd"
)

// warnOnOldSystemdVersion checks the version of Systemd
// in a given system and prints a warning if older than 240.
func (s *stage) warnOnOldSystemdVersion() error {
	systemdVersion, err := systemd.GetSystemdVersion(context.Background())
	if err != nil {
		return err
	}
	if systemdVersion < 240 {
		s.Warning("The version of systemd (%d) is less than 240. Enabling/disabling instantiated units may not work. See https://github.com/coreos/ignition/issues/586 for more information.", systemdVersion)
	}
	return nil
}

// applyUnits materializes unit files, dropins and mask/unmask links.
// Preset enablement is published separately by publishPresets.
func (s *stage) applyUnits(p *filesPlan) error {
	return s.applyTargets(p, phaseUnit)
}

// parseInstanceUnit extracts the name and a corresponding instance
// for a given instantiated unit.
// e.g: echo@bar.service ==> unitName=echo@.service & instance=bar
func parseInstanceUnit(unit types.Unit) (string, string, error) {
	at := strings.Index(unit.Name, "@")
	if at == -1 {
		return "", "", errors.ErrInvalidInstantiatedUnit
	}
	dot := strings.LastIndex(unit.Name, ".")
	if dot == -1 {
		return "", "", errors.ErrNoSystemdExt
	}
	instance := unit.Name[at+1 : dot]
	serviceInstance := unit.Name[0:at+1] + unit.Name[dot:len(unit.Name)]
	return serviceInstance, instance, nil
}

// publishPresets appends the enable/disable preset lines, one record at
// a time with each line confirmed so an interrupted run does not
// duplicate entries.  Disabled units also have their enablement symlinks
// removed via systemctl, mirroring util.DisableUnit.
func (s *stage) publishPresets(p *filesPlan) error {
	if len(p.cp.Presets) == 0 {
		p.cp.PresetsDone = true
		return p.save()
	}

	presetPath, err := s.JoinPath(util.PresetPath)
	if err != nil {
		return err
	}
	if s.relabeling() {
		if err := s.relabelPath(presetPath); err != nil {
			return err
		}
	}

	records := make([]presetRecord, len(p.cp.Presets))
	copy(records, p.cp.Presets)
	sort.Slice(records, func(i, j int) bool { return records[i].Key < records[j].Key })

	hasInstanceUnit := false
	for _, rec := range records {
		if rec.Instantiated {
			hasInstanceUnit = true
		}
		if rec.Confirmed {
			continue
		}
		directive := "enable"
		if !rec.Enabled {
			directive = "disable"
		}
		line := fmt.Sprintf("%s %s", directive, rec.UnitString)

		exists, err := presetLineExists(presetPath, line)
		if err != nil {
			return err
		}
		if !exists {
			if !rec.Enabled {
				if err := s.systemctlDisable(rec.UnitString); err != nil {
					return err
				}
			}
			if err := s.LogOp(func() error {
				return appendPresetLine(presetPath, line)
			}, "setting preset to %s for %q", directive, rec.UnitString); err != nil {
				return err
			}
		}

		// Confirm the line landed before recording progress.
		exists, err = presetLineExists(presetPath, line)
		if err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("preset line %q could not be confirmed in %s", line, presetPath)
		}
		p.markPresetConfirmed(rec.Key)
		if err := p.save(); err != nil {
			return err
		}
	}

	if hasInstanceUnit {
		if err := s.warnOnOldSystemdVersion(); err != nil {
			return err
		}
	}
	p.cp.PresetsDone = true
	return p.save()
}

func (p *filesPlan) markPresetConfirmed(key string) {
	for i := range p.cp.Presets {
		if p.cp.Presets[i].Key == key {
			p.cp.Presets[i].Confirmed = true
		}
	}
}

// systemctlDisable mirrors util.DisableUnit's symlink cleanup without
// touching the preset file.
func (s *stage) systemctlDisable(unitString string) error {
	// check if the unit is currently enabled to see if we need to disable it
	// if it's not enabled or does not exist, we don't need to do anything
	args := []string{"--root", s.DestDir, "is-enabled", unitString}
	if err := exec.Command(distro.SystemctlCmd(), args...).Run(); err != nil {
		return nil
	}
	// We need to delete any enablement symlinks for a unit before sending it to a
	// preset directive. This will help to disable that unit completely.
	// For more information: https://github.com/coreos/fedora-coreos-tracker/issues/392
	return s.LogOp(
		func() error {
			args := []string{"--root", s.DestDir, "disable", unitString}
			if output, err := exec.Command(distro.SystemctlCmd(), args...).CombinedOutput(); err != nil {
				return fmt.Errorf("cannot remove symlink(s) for %s: %v: %q", unitString, err, string(output))
			}
			return nil
		},
		"removing enablement symlink(s) for %q", unitString,
	)
}

// presetLineExists reports whether the exact preset directive line is
// already present in the preset file.
func presetLineExists(path, line string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	defer func() {
		_ = f.Close()
	}()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if scanner.Text() == line {
			return true, nil
		}
	}
	return false, scanner.Err()
}

// appendPresetLine appends one directive line to the preset file,
// repairing an unterminated previous line first.
func appendPresetLine(path, line string) error {
	if err := util.MkdirForFile(path); err != nil {
		return err
	}
	// If a previous invocation was interrupted mid-line, keep the new
	// directive from being concatenated onto the fragment.
	if info, err := os.Stat(path); err == nil && info.Size() > 0 {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		buf := make([]byte, 1)
		if _, err := f.ReadAt(buf, info.Size()-1); err != nil {
			_ = f.Close()
			return err
		}
		_ = f.Close()
		if buf[0] != '\n' {
			a, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				return err
			}
			if _, err := a.WriteString("\n"); err != nil {
				_ = a.Close()
				return err
			}
			_ = a.Close()
		}
	}

	file, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND|os.O_CREATE, util.DefaultPresetPermissions)
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
	}()
	if _, err := file.WriteString(line + "\n"); err != nil {
		return err
	}
	return nil
}
