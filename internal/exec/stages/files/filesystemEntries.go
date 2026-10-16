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
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	cutil "github.com/coreos/ignition/v2/config/util"
	"github.com/coreos/ignition/v2/config/v3_7_experimental/types"
	"github.com/coreos/ignition/v2/internal/distro"
	"github.com/coreos/ignition/v2/internal/exec/util"

	"github.com/vincent-petithory/dataurl"
)

// buildCrypttabOptions constructs the options suffix for a crypttab entry.
// It always adds x-initrd.attach and adds _netdev if network is needed.
// The x-initrd.attach option prevents systemd-cryptsetup-generator from
// adding Conflicts=umount.target, which is necessary for soft-reboot to
// work correctly with LUKS.
func buildCrypttabOptions(hasNetworkDev bool) string {
	options := "x-initrd.attach"
	if hasNetworkDev {
		options = "_netdev," + options
	}
	return "," + options
}

// buildLuksPlan plans the /etc/crypttab entry, LUKS keyfiles and CEX
// secure-key repository files as luks-phase targets.
func (s *stage) buildLuksPlan(config types.Config, p *filesPlan) error {
	if err := s.buildCrypttabPlan(config, p); err != nil {
		return err
	}
	return s.buildCexVolumeKeyPlan(config, p)
}

// buildCrypttabPlan plans entries inside of /etc/crypttab for LUKS
// volumes, as well as copying keyfiles to the sysroot.
func (s *stage) buildCrypttabPlan(config types.Config, p *filesPlan) error {
	if len(config.Storage.Luks) == 0 {
		return nil
	}

	s.PushPrefix("buildCrypttabPlan")
	defer s.PopPrefix()

	path, err := s.JoinPath("/etc/crypttab")
	if err != nil {
		return fmt.Errorf("building crypttab filepath: %v", err)
	}
	crypttab := types.File{
		Node: types.Node{
			Path: path,
		},
		FileEmbedded1: types.FileEmbedded1{
			Mode: cutil.IntToPtr(0600),
		},
	}
	var extrafiles []types.File
	for _, luks := range config.Storage.Luks {
		out, err := exec.Command(distro.CryptsetupCmd(), "luksUUID", util.DeviceAlias(*luks.Device)).CombinedOutput()
		if err != nil {
			return fmt.Errorf("gathering luks uuid: %s: %v", out, err)
		}
		uuid := strings.TrimSpace(string(out))
		hasNetworkDev := len(luks.Clevis.Tang) > 0 || cutil.NotEmpty(luks.Clevis.Custom.Pin) && cutil.IsTrue(luks.Clevis.Custom.NeedsNetwork)
		keyfile := "none"
		if !luks.Clevis.IsPresent() {
			keyfile = filepath.Join(distro.LuksRealRootKeyFilePath(), luks.Name)

			// Write keyfile into sysroot
			contentsUri, ok := s.State.LuksPersistKeyFiles[luks.Name]
			if !ok {
				return fmt.Errorf("missing persisted keyfile for %s", luks.Name)
			}
			keyfilePath, err := s.JoinPath(keyfile)
			if err != nil {
				return fmt.Errorf("building keyfile path: %v", err)
			}
			extrafiles = append(extrafiles, types.File{
				Node: types.Node{
					Path: keyfilePath,
				},
				FileEmbedded1: types.FileEmbedded1{
					Contents: types.Resource{
						Source: &contentsUri,
					},
					Mode: cutil.IntToPtr(0600),
				},
			})
		}
		options := buildCrypttabOptions(hasNetworkDev)
		uri := dataurl.EncodeBytes([]byte(fmt.Sprintf("%s UUID=%s %s luks%s\n", luks.Name, uuid, keyfile, options)))
		crypttab.Append = append(crypttab.Append, types.Resource{
			Source: &uri,
		})
	}
	// if we're creating keyfiles we want to write the containing directory (if it doesn't
	// already exist) to be mode 0700 rather than auto-creating it at the default directory
	// permission
	if len(extrafiles) > 0 {
		realpath, err := s.JoinPath(distro.LuksRealRootKeyFilePath())
		if err != nil {
			return fmt.Errorf("building keyfile dir path: %v", err)
		}
		if _, err := os.Stat(realpath); err != nil {
			if !os.IsNotExist(err) {
				return fmt.Errorf("checking if keyfile dir exists: %v", err)
			}
			d := types.Directory{
				Node: types.Node{
					Path: realpath,
				},
				DirectoryEmbedded1: types.DirectoryEmbedded1{
					Mode: cutil.IntToPtr(0700),
				},
			}
			if err := s.addDirectoryInPhase(p, phaseLuks, d); err != nil {
				return err
			}
		}
	}
	for _, f := range extrafiles {
		if _, err := s.addFileTarget(p, f, phaseLuks, "luks keyfile"); err != nil {
			return fmt.Errorf("adding luks keyfile: %v", err)
		}
	}
	if _, err := s.addFileTarget(p, crypttab, phaseLuks, "crypttab"); err != nil {
		return fmt.Errorf("adding crypttab: %v", err)
	}
	return nil
}

// buildProviderPlan plans any files saved in state by provider
// fetch.
func (s *stage) buildProviderPlan(p *filesPlan) error {
	for _, file := range s.State.ProviderOutputFiles {
		path, err := s.JoinPath(file.Path)
		if err != nil {
			return fmt.Errorf("calculating path for %q: %w", file.Path, err)
		}
		file.Path = path
		if _, err := s.addFileTarget(p, file, phasePublish, "provider output"); err != nil {
			return err
		}
	}
	return nil
}

// buildResultData renders the report recording details about the
// Ignition run.
func (s *stage) buildResultData() ([]byte, error) {
	var prevReport interface{}
	prevPath, err := s.JoinPath(distro.ResultFilePath())
	if err != nil {
		return nil, fmt.Errorf("building previous result file path: %w", err)
	}
	prevData, err := os.ReadFile(prevPath)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("reading previous report: %w", err)
	}
	if err == nil {
		// To check if it's a live system
		if err := exec.Command("is-live-image").Run(); err != nil {
			if _, ok := err.(*exec.ExitError); !ok {
				s.Notice("failed to run is-live-image hook: %v", err)
			}
			s.Warning("Ignition has already run on this system. Unexpected behavior may occur. Ignition is not designed to run more than once per system.")
			if err := json.Unmarshal(prevData, &prevReport); err != nil {
				return nil, fmt.Errorf("couldn't unmarshal previous report output: %v", err)
			}
		}
	}

	bootIDBytes, err := os.ReadFile(distro.BootIDPath())
	if err != nil {
		return nil, fmt.Errorf("reading boot ID: %w", err)
	}

	result := struct {
		ProvisioningBootID string      `json:"provisioningBootID"`
		ProvisioningDate   string      `json:"provisioningDate"`
		UserConfigProvided bool        `json:"userConfigProvided"`
		PreviousReport     interface{} `json:"previousReport,omitempty"`
	}{
		ProvisioningBootID: strings.TrimSpace(string(bootIDBytes)),
		ProvisioningDate:   time.Now().Format(time.RFC3339),
		PreviousReport:     prevReport,
	}
	for _, config := range s.State.FetchedConfigs {
		if config.Kind == "user" {
			result.UserConfigProvided = true
			break
		}
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling result file: %w", err)
	}
	data = append(data, '\n')
	return data, nil
}

// filesystemEntry represent a thing that knows its node.  The concrete
// entry types are retained for tests and plan construction helpers.
type filesystemEntry interface {
	node() types.Node
}

type fileEntry types.File

func (tmp fileEntry) node() types.Node {
	return types.File(tmp).Node
}

type dirEntry types.Directory

func (tmp dirEntry) node() types.Node {
	return types.Directory(tmp).Node
}

type linkEntry types.Link

func (tmp linkEntry) node() types.Node {
	return types.Link(tmp).Node
}

// relabelPath schedules relabeling for the path. The first component which was
// found to be missing is used, or the whole path if it already exists.
func (s *stage) relabelPath(path string) error {
	if !s.relabeling() {
		return nil
	}

	missingPath, err := util.FindFirstMissingPathComponent(path)
	if err != nil {
		return err
	}

	// trim off prefix since this needs to be relative to the sysroot
	s.relabel(missingPath[len(s.DestDir):])
	return nil
}

// scheduleRelabel records the target's relabel path, replaying the
// original selection on a resumed run so a created directory subtree is
// still covered.
func (s *stage) scheduleRelabel(t *plannedTarget) error {
	if !s.relabeling() {
		return nil
	}
	if t.Relabel == "" {
		if err := s.relabelPath(t.Path); err != nil {
			return err
		}
		missingPath, err := util.FindFirstMissingPathComponent(t.Path)
		if err != nil {
			return err
		}
		t.Relabel = missingPath[len(s.DestDir):]
	} else {
		s.relabel(t.Relabel)
	}
	return nil
}

// replayTargetRelabels re-adds every planned target's relabel
// selection, including confirmed ones, so a resumed run still labels
// everything the previous invocation created.
func (s *stage) replayTargetRelabels(p *filesPlan) {
	for _, t := range p.cp.Targets {
		if err := s.scheduleRelabel(t); err != nil {
			s.Warning("failed to schedule relabel for %s: %v", t.Path, err)
		}
	}
}

// applyTargets applies every unconfirmed target of a phase, in plan
// order.  Confirmed targets still contribute their relabel selection.
func (s *stage) applyTargets(p *filesPlan, phase string) error {
	for _, t := range p.targetsInPhase(phase) {
		if err := s.applyTarget(p, t); err != nil {
			return err
		}
	}
	return nil
}

// applyTarget guards, materializes and verifies a single target.
func (s *stage) applyTarget(p *filesPlan, t *plannedTarget) error {
	if !strings.HasPrefix(t.Path, s.DestDir) {
		panic(fmt.Sprintf("Target path %s isn't under prefix %s", t.Path, s.DestDir))
	}

	if err := s.scheduleRelabel(t); err != nil {
		return fmt.Errorf("error relabeling paths for %s: %v", t.Path, err)
	}

	if t.Confirmed {
		return nil
	}

	if !t.Overwrite && !t.Chained && t.Kind != kindMask {
		alreadyDesired, err := s.guardTarget(t)
		if err != nil {
			return err
		}
		if alreadyDesired {
			t.Confirmed = true
			return p.save()
		}
	} else if t.Overwrite || t.Kind == kindMask {
		// Explicit overwrite or mask: the plan owns whatever is there.
		if err := os.RemoveAll(t.Path); err != nil {
			return fmt.Errorf("error removing existing file %s: %v", t.Path, err)
		}
	}

	if err := s.materializeTarget(p, t); err != nil {
		return err
	}
	if err := s.verifyTarget(t); err != nil {
		return err
	}

	t.Confirmed = true
	return p.save()
}

// guardTarget verifies that a target the plan has not confirmed yet is
// still either in the state captured by the plan or already matching the
// desired end state.  Anything else is rejected as an external
// modification.
func (s *stage) guardTarget(t *plannedTarget) (bool, error) {
	cur, err := captureIdentity(t.Path, false)
	if err != nil {
		return false, err
	}

	snapshotMatches := false
	if t.Original == nil || !t.Original.Exists {
		snapshotMatches = !cur.Exists
	} else if sameIdentity(cur, t.Original) {
		snapshotMatches = true
	}

	// For files extended with Append resources, the existing bytes are
	// part of the pinned identity too.
	if snapshotMatches && t.PrefixObj != "" && cur.Exists {
		got, err := hashRegularFile(t.Path)
		if err != nil {
			return false, err
		}
		if !bytesEqual(got, t.Original.ContentSum) {
			snapshotMatches = false
		}
	}

	if !snapshotMatches {
		desired, err := s.targetMatchesDesired(t, cur)
		if err != nil {
			return false, err
		}
		if !desired {
			return false, fmt.Errorf("%w: %q", ErrTargetModifiedExternally, t.Path)
		}
		return true, nil
	}
	return false, nil
}

// targetMatchesDesired reports whether the current state already equals
// the planned end state, allowing the stage to adopt work finished
// immediately before a process exit.
func (s *stage) targetMatchesDesired(t *plannedTarget, cur *targetIdentity) (bool, error) {
	if !cur.Exists {
		return t.Kind == kindUnmask, nil
	}
	switch t.Kind {
	case targetTypeDir:
		return cur.Type == targetTypeDir, nil
	case targetTypeFile:
		if cur.Type != targetTypeFile || t.FinalSum == nil {
			return false, nil
		}
		return verifyRegularFileContent(t.Path, t.FinalSum)
	case targetTypeSymlink:
		return cur.Type == targetTypeSymlink &&
			filepath.Clean(cur.LinkTarget) == filepath.Clean(t.LinkTarget), nil
	case kindHardlink:
		if cur.Type != targetTypeFile {
			return false, nil
		}
		st, err := os.Lstat(t.Path)
		if err != nil {
			return false, err
		}
		targetst, err := os.Lstat(t.LinkTarget)
		if err != nil {
			return false, nil
		}
		return os.SameFile(st, targetst), nil
	case kindMask:
		return cur.Type == targetTypeSymlink && cur.LinkTarget == "/dev/null", nil
	case kindUnmask:
		return !(cur.Type == targetTypeSymlink && cur.LinkTarget == "/dev/null"), nil
	default:
		return false, nil
	}
}

// materializeTarget creates or replaces the target on disk.
func (s *stage) materializeTarget(p *filesPlan, t *plannedTarget) error {
	switch t.Kind {
	case targetTypeDir:
		if err := os.MkdirAll(t.Path, util.DefaultDirectoryPermissions); err != nil {
			return fmt.Errorf("failed to create directory %s: %v", t.Path, err)
		}
	case targetTypeFile:
		if err := s.writePlannedFile(p, t); err != nil {
			return err
		}
	case targetTypeSymlink:
		if err := util.MkdirForFile(t.Path); err != nil {
			return fmt.Errorf("could not create leading directories: %v", err)
		}
		if err := os.Symlink(t.LinkTarget, t.Path); err != nil {
			return fmt.Errorf("could not create symlink: %v", err)
		}
	case kindHardlink:
		if err := util.MkdirForFile(t.Path); err != nil {
			return fmt.Errorf("could not create leading directories: %v", err)
		}
		if err := os.Link(t.LinkTarget, t.Path); err != nil {
			return fmt.Errorf("failed to create hard link %s: %v", t.Path, err)
		}
	case kindMask:
		if err := util.MkdirForFile(t.Path); err != nil {
			return fmt.Errorf("could not create leading directories: %v", err)
		}
		if err := os.RemoveAll(t.Path); err != nil {
			return err
		}
		if err := os.Symlink("/dev/null", t.Path); err != nil {
			return fmt.Errorf("could not mask unit: %v", err)
		}
	case kindUnmask:
		id, err := captureIdentity(t.Path, false)
		if err != nil {
			return err
		}
		if id.Exists && id.Type == targetTypeSymlink && id.LinkTarget == "/dev/null" {
			if err := os.Remove(t.Path); err != nil {
				return fmt.Errorf("unmasking unit %s: %v", t.Path, err)
			}
		}
	default:
		return fmt.Errorf("unknown target kind %q for %s", t.Kind, t.Path)
	}
	return nil
}

// writePlannedFile composes the final content from staged objects and
// atomically replaces the destination.
func (s *stage) writePlannedFile(p *filesPlan, t *plannedTarget) error {
	if t.FinalSum == nil {
		// Existing content must be preserved.
		return nil
	}
	if err := util.MkdirForFile(t.Path); err != nil {
		return err
	}

	// Compose into a temporary file in the same directory so the
	// rename is atomic and on the same filesystem.
	tmp, err := os.CreateTemp(filepath.Dir(t.Path), "tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}

	// os.CreateTemp defaults to 0600; unit/file contents default to
	// 0644 until the identity phase sets the configured mode.
	if err := tmp.Chmod(util.DefaultFilePermissions); err != nil {
		cleanup()
		return err
	}
	// Append-only entries replace a pre-existing file; preserve its
	// ownership and mode unless the config overrides them, matching the
	// former in-place append behavior.
	if t.PrefixObj != "" && t.Original != nil && t.Original.Exists {
		if err := tmp.Chown(t.Original.Uid, t.Original.Gid); err != nil {
			cleanup()
			return fmt.Errorf("preserving ownership of %q: %v", t.Path, err)
		}
		if err := tmp.Chmod(util.ToFileMode(int(t.Original.Mode))); err != nil {
			cleanup()
			return fmt.Errorf("preserving mode of %q: %v", t.Path, err)
		}
	}

	h := sha256.New()
	write := func(data []byte) error {
		if _, err := h.Write(data); err != nil {
			return err
		}
		_, err := tmp.Write(data)
		return err
	}
	if t.PrefixObj != "" {
		data, err := p.readObject(t.PrefixObj)
		if err != nil {
			cleanup()
			return fmt.Errorf("reading staged prefix for %q: %v", t.Path, err)
		}
		if err := write(data); err != nil {
			cleanup()
			return err
		}
	}
	for _, f := range t.Fetches {
		data, err := p.readObject(f.Obj)
		if err != nil {
			cleanup()
			return fmt.Errorf("reading staged content for %q: %v", t.Path, err)
		}
		if err := write(data); err != nil {
			cleanup()
			return err
		}
	}
	if !bytes.Equal(h.Sum(nil), t.FinalSum) {
		cleanup()
		return fmt.Errorf("internal error composing %q: content checksum mismatch", t.Path)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, t.Path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

// verifyTarget confirms the on-disk target matches the plan after
// materialization.
func (s *stage) verifyTarget(t *plannedTarget) error {
	id, err := captureIdentity(t.Path, false)
	if err != nil {
		return err
	}
	switch t.Kind {
	case targetTypeDir:
		if !id.Exists || id.Type != targetTypeDir {
			return fmt.Errorf("directory %q was not created as expected", t.Path)
		}
	case targetTypeFile:
		if !id.Exists || id.Type != targetTypeFile {
			return fmt.Errorf("file %q was not created as expected", t.Path)
		}
		if t.FinalSum != nil {
			ok, err := verifyRegularFileContent(t.Path, t.FinalSum)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("file %q content checksum mismatch after write", t.Path)
			}
		}
	case targetTypeSymlink:
		if !id.Exists || id.Type != targetTypeSymlink ||
			filepath.Clean(id.LinkTarget) != filepath.Clean(t.LinkTarget) {
			return fmt.Errorf("symlink %q does not point to %q after write", t.Path, t.LinkTarget)
		}
	case kindHardlink:
		st, err := os.Lstat(t.Path)
		if err != nil {
			return err
		}
		targetst, err := os.Lstat(t.LinkTarget)
		if err != nil {
			return fmt.Errorf("hard link target %s: %v", t.LinkTarget, err)
		}
		if !os.SameFile(st, targetst) {
			return fmt.Errorf("hard link %q does not reference %q", t.Path, t.LinkTarget)
		}
	case kindMask:
		if !id.Exists || id.Type != targetTypeSymlink || id.LinkTarget != "/dev/null" {
			return fmt.Errorf("unit %q is not masked as expected", t.Path)
		}
	case kindUnmask:
		if id.Exists && id.Type == targetTypeSymlink && id.LinkTarget == "/dev/null" {
			return fmt.Errorf("unit %q is still masked after unmask", t.Path)
		}
	}
	return nil
}

// applyIdentities applies ownership and mode to the targets of the given
// phases and verifies the result.  It runs after users/groups have been
// reconciled so name-based ownership can be resolved.
func (s *stage) applyIdentities(p *filesPlan, phases ...string) error {
	want := map[string]bool{}
	for _, phase := range phases {
		want[phase] = true
	}
	for _, t := range p.cp.Targets {
		if !want[t.Phase] || t.PermDone || t.Node == nil {
			continue
		}
		// Unconfirmed targets should have failed earlier, but be explicit.
		if !t.Confirmed && t.Kind != targetTypeDir {
			continue
		}
		if t.Kind != targetTypeDir && t.Kind != targetTypeFile &&
			t.Kind != targetTypeSymlink && t.Kind != kindHardlink {
			continue
		}
		if err := s.SetPermissions(t.Mode, *t.Node); err != nil {
			return fmt.Errorf("error setting permissions for %s: %v", t.Path, err)
		}
		if err := s.verifyIdentity(t); err != nil {
			return err
		}
		t.PermDone = true
		if err := p.save(); err != nil {
			return err
		}
	}
	return nil
}

// verifyIdentity verifies configured uid/gid/mode after applying them.
func (s *stage) verifyIdentity(t *plannedTarget) error {
	id, err := captureIdentity(t.Path, false)
	if err != nil {
		return err
	}
	if !id.Exists {
		return fmt.Errorf("target %q vanished while setting permissions", t.Path)
	}
	if t.Mode != nil && id.Mode != uint32(*t.Mode)&07777 {
		return fmt.Errorf("target %q mode %o does not match expected %o", t.Path, id.Mode, *t.Mode)
	}
	defaultUid, defaultGid := id.Uid, id.Gid
	uid, gid, err := s.ResolveNodeUidAndGid(*t.Node, defaultUid, defaultGid)
	if err != nil {
		return fmt.Errorf("failed to determine correct uid and gid for %s: %v", t.Path, err)
	}
	if t.Node.User.ID != nil || cutil.NotEmpty(t.Node.User.Name) {
		if id.Uid != uid {
			return fmt.Errorf("target %q uid %d does not match expected %d", t.Path, id.Uid, uid)
		}
	}
	if t.Node.Group.ID != nil || cutil.NotEmpty(t.Node.Group.Name) {
		if id.Gid != gid {
			return fmt.Errorf("target %q gid %d does not match expected %d", t.Path, id.Gid, gid)
		}
	}
	return nil
}

// buildCexVolumeKeyPlan plans the CEX secure key repository files.
func (s *stage) buildCexVolumeKeyPlan(config types.Config, p *filesPlan) error {
	if len(config.Storage.Luks) == 0 {
		return nil
	}
	s.PushPrefix("buildCexVolumeKeyPlan")
	defer s.PopPrefix()
	for _, luks := range config.Storage.Luks {
		if !luks.Cex.IsPresent() {
			continue
		}
		// zkey generates, validates and reencipher secure key. The information file
		// which contains the description about keys for key management.
		fileExt := util.ZkeySecureKeyRepoFiles(luks.Name)
		for zkeyExt, zfile := range fileExt {
			zkeyFile := filepath.Join(distro.LuksRealVolumeKeyFilePath(), zfile)
			// Write zkeyfiles into sysroot
			contentsUri, ok := s.State.LuksPersistSecureKeyRepoFiles[zfile]
			if !ok {
				return fmt.Errorf("missing persisted zkeyfile for %s", zkeyFile)
			}
			zkeyFilepath, err := s.JoinPath(zkeyFile)
			if err != nil {
				return fmt.Errorf("building zkeyfile path: %v", err)
			}
			f := types.File{
				Node: types.Node{
					Path: zkeyFilepath,
				},
				FileEmbedded1: types.FileEmbedded1{
					Contents: types.Resource{
						Source: &contentsUri,
					},
					Mode: cutil.IntToPtr(0600),
				},
			}
			if _, err := s.addFileTarget(p, f, phaseLuks, "cex key"); err != nil {
				return fmt.Errorf("adding luks volume related file %q: %v", zkeyExt, err)
			}
		}
	}
	return nil
}
