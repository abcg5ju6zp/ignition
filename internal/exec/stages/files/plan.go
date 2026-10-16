// Copyright 2026 CoreOS, Inc.
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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	cutil "github.com/coreos/ignition/v2/config/util"
	"github.com/coreos/ignition/v2/config/v3_7_experimental/types"
	"github.com/coreos/ignition/v2/internal/distro"
	"github.com/coreos/ignition/v2/internal/exec/util"

	"github.com/vincent-petithory/dataurl"
)

const (
	checkpointVersion = 1
	checkpointName    = "checkpoint.json"
	objectsDirName    = "objects"

	phaseStorage = "storage"
	phaseLuks    = "luks"
	phaseUnit    = "unit"
	phasePublish = "publish"

	kindHardlink = "hardlink"
	kindMask     = "mask"
	kindUnmask   = "unmask"
)

// stagedFetch records one fetched content object held in the staging
// directory, already verified.
type stagedFetch struct {
	// Obj is the content-addressed object name within the objects dir.
	Obj string `json:"obj"`
	// Append distinguishes append resources from the main contents.
	Append bool `json:"append"`
	// Sum is the actual content checksum.
	Sum []byte `json:"sum"`
}

// plannedTarget is a single filesystem object the stage is responsible
// for, along with the pinned identity of whatever was there before and
// the confirmation state.
type plannedTarget struct {
	Path      string          `json:"path"`
	Kind      string          `json:"kind"`
	Phase     string          `json:"phase"`
	Overwrite bool            `json:"overwrite,omitempty"`
	Original  *targetIdentity `json:"original,omitempty"`
	// Confirmed means the on-disk content/type already matches the plan.
	Confirmed bool `json:"confirmed"`
	// PermDone means ownership and mode have been applied and verified.
	PermDone bool `json:"permDone"`
	// Relabel is the relabeling path scheduled when this target was
	// first prepared, so resume runs keep covering originally created
	// directory subtrees.
	Relabel string `json:"relabel,omitempty"`

	// Ownership and mode specifications.
	Mode *int        `json:"mode,omitempty"`
	Node *types.Node `json:"node,omitempty"`

	// Link configuration: symlink target as written for symlinks, or
	// the sysroot-absolute hard link target for verification.
	LinkTarget string `json:"linkTarget,omitempty"`

	// PrefixObj names the staged object holding the bytes of a
	// pre-existing file when Append resources extend it.
	PrefixObj string `json:"prefixObj,omitempty"`
	// Fetches are the staged contents in application order.
	Fetches []stagedFetch `json:"fetches,omitempty"`
	// FinalSum is the expected SHA-256 of the file's final content. A
	// nil sum means the content of an existing file must be preserved.
	FinalSum []byte `json:"finalSum,omitempty"`

	// Chained marks a target whose path was already handled by an
	// earlier target in this plan (e.g. mask after writing a unit); the
	// external-modification guard is skipped.
	Chained bool `json:"chained,omitempty"`

	// Label is used for log messages.
	Label string `json:"label,omitempty"`

	// ops is the transient set of fetch operations; it is rebuilt on
	// every run and never serialized.
	ops []util.FetchOp `json:"-"`
}

// groupRecord tracks confirmation state for a configured group.
type groupRecord struct {
	Name     string `json:"name"`
	Ensured  bool   `json:"ensured"`
	Deleted  bool   `json:"deleted"`
	Gid      bool   `json:"gid"`
	Password bool   `json:"password"`
}

// userRecord tracks confirmation state for a configured user.
type userRecord struct {
	Name string `json:"name"`
	// Ensured means the user's existence matches the plan.
	Ensured bool `json:"ensured"`
	Deleted bool `json:"deleted"`
	// Per-attribute confirmation; an attribute is only touched when its
	// bit is unset and the config specifies it.
	UID          bool `json:"uid"`
	PrimaryGroup bool `json:"primaryGroup"`
	Groups       bool `json:"groups"`
	Shell        bool `json:"shell"`
	Gecos        bool `json:"gecos"`
	Home         bool `json:"home"`
	Password     bool `json:"password"`
	HomePerms    bool `json:"homePerms"`
	Keys         bool `json:"keys"`
}

// presetRecord tracks one enable/disable preset line.
type presetRecord struct {
	Key          string `json:"key"`
	UnitString   string `json:"unitString"`
	Enabled      bool   `json:"enabled"`
	Instantiated bool   `json:"instantiated"`
	Confirmed    bool   `json:"confirmed"`
}

// filesCheckpoint is the on-disk resume state for the files stage.
type filesCheckpoint struct {
	Version    int    `json:"version"`
	Generation string `json:"generation"`
	Root       string `json:"root"`

	Targets []*plannedTarget `json:"targets"`
	Groups  []groupRecord    `json:"groups"`
	Users   []userRecord     `json:"users"`
	Presets []presetRecord   `json:"presets"`

	FetchDone          bool `json:"fetchDone"`
	RelabelContentDone bool `json:"relabelContentDone"`
	PresetsDone        bool `json:"presetsDone"`
	ProviderDone       bool `json:"providerDone"`
	ResultDone         bool `json:"resultDone"`
	RelabelPublishDone bool `json:"relabelPublishDone"`
	Completed          bool `json:"completed"`
}

// filesPlan carries the checkpoint and its staging area for one stage
// invocation.
type filesPlan struct {
	cp *filesCheckpoint
	// prev is the checkpoint adopted from a previous invocation, used
	// only while building the fresh manifest.
	prev       *filesCheckpoint
	persistent bool
	dir        string
	objectsDir string
	isApply    bool
}

func (p *filesPlan) checkpointPath() string {
	return filepath.Join(p.dir, checkpointName)
}

// configGeneration pins the config "generation": a digest of the merged
// config and the sysroot the stage operates on.
func configGeneration(config types.Config, root string) (string, error) {
	b, err := json.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("marshaling config for generation digest: %v", err)
	}
	h := sha256.New()
	h.Write(b)
	h.Write([]byte(root))
	return hex.EncodeToString(h.Sum(nil)), nil
}

// targetKey identifies a target across a resumed invocation.
func targetKey(t *plannedTarget) string {
	return t.Phase + "\x00" + t.Kind + "\x00" + t.Path
}

// initPlan creates a fresh plan and adopts an existing checkpoint when it
// belongs to the same generation and root.
func (s *stage) initPlan(config types.Config, isApply bool) (*filesPlan, error) {
	generation, err := configGeneration(config, s.DestDir)
	if err != nil {
		return nil, err
	}

	p := &filesPlan{
		cp: &filesCheckpoint{
			Version:    checkpointVersion,
			Generation: generation,
			Root:       s.DestDir,
		},
		isApply: isApply,
	}

	if isApply {
		// Container flow: keep everything in a temporary staging dir
		// and never checkpoint.
		dir, err := os.MkdirTemp("", "ignition-files-stage-")
		if err != nil {
			return nil, fmt.Errorf("creating staging directory: %v", err)
		}
		p.dir = dir
	} else {
		p.persistent = true
		p.dir = distro.FilesStageDir()

		prev, err := loadCheckpoint(p.checkpointPath())
		if err != nil {
			return nil, err
		}
		if prev != nil && prev.Version == checkpointVersion &&
			prev.Generation == generation && prev.Root == s.DestDir {
			p.prev = prev
			s.Info("resuming files stage from checkpoint %s", p.checkpointPath())
			p.cp.FetchDone = prev.FetchDone
			p.cp.RelabelContentDone = prev.RelabelContentDone
			p.cp.PresetsDone = prev.PresetsDone
			p.cp.ProviderDone = prev.ProviderDone
			p.cp.ResultDone = prev.ResultDone
			p.cp.RelabelPublishDone = prev.RelabelPublishDone
			p.cp.Completed = prev.Completed
		} else if prev != nil {
			// A different generation: its plan must never be used to
			// overwrite targets, so drop it and its staged contents and
			// re-plan from the current state of the world.
			s.Info("discarding stale files stage checkpoint for generation %s", prev.Generation)
			if err := os.RemoveAll(p.dir); err != nil {
				return nil, fmt.Errorf("removing stale stage directory: %v", err)
			}
		}
	}

	p.objectsDir = filepath.Join(p.dir, objectsDirName)
	if err := os.MkdirAll(p.objectsDir, 0700); err != nil {
		return nil, fmt.Errorf("creating staging objects directory: %v", err)
	}

	return p, nil
}

// loadCheckpoint reads a checkpoint.  A missing file yields nil, nil.
func loadCheckpoint(path string) (*filesCheckpoint, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("reading files stage checkpoint: %v", err)
	}
	var cp filesCheckpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		return nil, fmt.Errorf("parsing files stage checkpoint: %v", err)
	}
	return &cp, nil
}

// save persists the checkpoint atomically.  It is a no-op for the
// non-persistent (ignition-apply) flow.
func (p *filesPlan) save() error {
	if !p.persistent {
		return nil
	}
	if err := os.MkdirAll(p.dir, 0700); err != nil {
		return fmt.Errorf("creating stage directory: %v", err)
	}
	data, err := json.Marshal(p.cp)
	if err != nil {
		return fmt.Errorf("serializing checkpoint: %v", err)
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(p.dir, ".checkpoint-")
	if err != nil {
		return fmt.Errorf("creating checkpoint temp file: %v", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("writing checkpoint: %v", err)
	}
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("setting checkpoint permissions: %v", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("closing checkpoint: %v", err)
	}
	if err := os.Rename(tmpName, p.checkpointPath()); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("publishing checkpoint: %v", err)
	}
	return nil
}

// cleanup removes the staging directory and checkpoint after successful
// completion.
func (p *filesPlan) cleanup() {
	if p == nil || p.dir == "" {
		return
	}
	_ = os.RemoveAll(p.dir)
}

// adoptTarget overlays confirmation state from the previous checkpoint.
func (p *filesPlan) adoptTarget(fresh *plannedTarget) {
	if p.prev == nil {
		return
	}
	for _, old := range p.prev.Targets {
		if targetKey(old) == targetKey(fresh) {
			fresh.Original = old.Original
			fresh.Confirmed = old.Confirmed
			fresh.PermDone = old.PermDone
			fresh.Relabel = old.Relabel
			fresh.PrefixObj = old.PrefixObj
			fresh.Fetches = old.Fetches
			fresh.FinalSum = old.FinalSum
			return
		}
	}
}

func (p *filesPlan) addTarget(t *plannedTarget) {
	p.adoptTarget(t)
	p.cp.Targets = append(p.cp.Targets, t)
}

func (p *filesPlan) groupRecord(name string) *groupRecord {
	for i := range p.cp.Groups {
		if p.cp.Groups[i].Name == name {
			return &p.cp.Groups[i]
		}
	}
	rec := groupRecord{Name: name}
	if p.prev != nil {
		for _, old := range p.prev.Groups {
			if old.Name == name {
				rec = old
				break
			}
		}
	}
	p.cp.Groups = append(p.cp.Groups, rec)
	return &p.cp.Groups[len(p.cp.Groups)-1]
}

func (p *filesPlan) userRecord(name string) *userRecord {
	for i := range p.cp.Users {
		if p.cp.Users[i].Name == name {
			return &p.cp.Users[i]
		}
	}
	rec := userRecord{Name: name}
	if p.prev != nil {
		for _, old := range p.prev.Users {
			if old.Name == name {
				rec = old
				break
			}
		}
	}
	p.cp.Users = append(p.cp.Users, rec)
	return &p.cp.Users[len(p.cp.Users)-1]
}

func (p *filesPlan) addPreset(rec presetRecord) {
	if p.prev != nil {
		for _, old := range p.prev.Presets {
			if old.Key == rec.Key {
				rec.Confirmed = old.Confirmed
				break
			}
		}
	}
	for i := range p.cp.Presets {
		if p.cp.Presets[i].Key == rec.Key {
			p.cp.Presets[i].Confirmed = rec.Confirmed
			return
		}
	}
	p.cp.Presets = append(p.cp.Presets, rec)
}

// targetsInPhase returns the planned targets for a phase, in order.
func (p *filesPlan) targetsInPhase(phase string) []*plannedTarget {
	var out []*plannedTarget
	for _, t := range p.cp.Targets {
		if t.Phase == phase {
			out = append(out, t)
		}
	}
	return out
}

// findTarget returns the target matching phase/kind/path, if any.
func (p *filesPlan) findTarget(phase, kind, path string) *plannedTarget {
	for _, t := range p.cp.Targets {
		if t.Phase == phase && t.Kind == kind && t.Path == path {
			return t
		}
	}
	return nil
}

// targetPlanned reports whether the target is already part of either a
// resumed checkpoint or the current build.  Build-time conflict checks
// are skipped for such targets; the guard at application time decides
// whether current state is safe to adopt or must be rejected.
func (p *filesPlan) targetPlanned(phase, kind, path string) bool {
	key := phase + "\x00" + kind + "\x00" + path
	if p.prev != nil {
		for _, t := range p.prev.Targets {
			if targetKey(t) == key {
				return true
			}
		}
	}
	for _, t := range p.cp.Targets {
		if targetKey(t) == key {
			return true
		}
	}
	return false
}

// storeObject stages content bytes under a content-addressed name and
// returns the name.
func (p *filesPlan) storeObject(data []byte) (string, error) {
	sum := sha256.Sum256(data)
	name := "obj-" + hex.EncodeToString(sum[:])
	path := filepath.Join(p.objectsDir, name)
	if _, err := os.Stat(path); err == nil {
		return name, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	tmp, err := os.CreateTemp(p.objectsDir, ".obj-")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return "", err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return "", err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return "", err
	}
	return name, nil
}

func (p *filesPlan) objectPath(name string) string {
	return filepath.Join(p.objectsDir, name)
}

// readObject returns the content of a staged object.
func (p *filesPlan) readObject(name string) ([]byte, error) {
	return os.ReadFile(p.objectPath(name))
}

// objectOK verifies a staged object exists and matches its checksum.
func (p *filesPlan) objectOK(f stagedFetch) bool {
	data, err := p.readObject(f.Obj)
	if err != nil {
		return false
	}
	return bytesEqual(hashBytes(data), f.Sum)
}

// addFileTarget converts a types.File (with a sysroot-absolute path) into
// a planned target and registers it.
func (s *stage) addFileTarget(p *filesPlan, f types.File, phase, label string) (*plannedTarget, error) {
	t := &plannedTarget{
		Path:      f.Path,
		Kind:      targetTypeFile,
		Phase:     phase,
		Overwrite: cutil.IsTrue(f.Overwrite),
		Mode:      f.Mode,
		Node:      &f.Node,
		Label:     label,
	}

	existing, err := captureIdentity(f.Path, false)
	if err != nil {
		return nil, err
	}
	if !t.Overwrite && !p.targetPlanned(phase, targetTypeFile, f.Path) {
		switch {
		case existing.Exists && existing.Type != targetTypeFile:
			return nil, fmt.Errorf("error creating file %q: a non regular file exists there already and overwrite is false", f.Path)
		case existing.Exists && f.Contents.Source != nil:
			return nil, fmt.Errorf("error creating file %q: a file exists there already and overwrite is false", f.Path)
		}
	}
	t.Original = existing

	ops, err := s.Util.PrepareFetches(s.Logger, f)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve file %q: %v", f.Path, err)
	}
	t.ops = ops
	s.prepareExistingPrefix(p, t)
	p.addTarget(t)
	return t, nil
}

// prepareExistingPrefix stages the current content of a file that only
// has Append resources, so the final content can be composed and written
// atomically.
func (s *stage) prepareExistingPrefix(p *filesPlan, t *plannedTarget) {
	if t.Overwrite || t.Original == nil || !t.Original.Exists || t.Original.Type != targetTypeFile {
		return
	}
	hasAppend := false
	for _, op := range t.ops {
		if op.Append {
			hasAppend = true
		}
	}
	if !hasAppend {
		return
	}
	data, err := os.ReadFile(t.Path)
	if err != nil {
		s.Warning("could not snapshot existing file %q: %v", t.Path, err)
		return
	}
	if name, err := p.storeObject(data); err == nil {
		t.PrefixObj = name
		t.Original.ContentSum = hashBytes(data)
	}
}

// addDirectoryTarget converts a types.Directory with sysroot-absolute
// path into a planned target.
func (s *stage) addDirectoryTarget(p *filesPlan, d types.Directory) (*plannedTarget, error) {
	return s.addDirectoryTargetIn(p, phaseStorage, d)
}

// addDirectoryInPhase registers a directory target in the given phase.
func (s *stage) addDirectoryInPhase(p *filesPlan, phase string, d types.Directory) error {
	_, err := s.addDirectoryTargetIn(p, phase, d)
	return err
}

// addDirectoryTargetIn is the phase-aware directory target builder.
func (s *stage) addDirectoryTargetIn(p *filesPlan, phase string, d types.Directory) (*plannedTarget, error) {
	t := &plannedTarget{
		Path:      d.Path,
		Kind:      targetTypeDir,
		Phase:     phase,
		Overwrite: cutil.IsTrue(d.Overwrite),
		Mode:      d.Mode,
		Node:      &d.Node,
	}
	existing, err := captureIdentity(d.Path, false)
	if err != nil {
		return nil, err
	}
	if !t.Overwrite && existing.Exists && existing.Type != targetTypeDir &&
		!p.targetPlanned(phase, targetTypeDir, d.Path) {
		return nil, fmt.Errorf("error creating directory %s: a non-directory already exists and overwrite is false", d.Path)
	}
	t.Original = existing
	p.addTarget(t)
	return t, nil
}

// addLinkTarget converts a types.Link with sysroot-absolute path.
func (s *stage) addLinkTarget(p *filesPlan, l types.Link) (*plannedTarget, error) {
	hard := cutil.IsTrue(l.Hard)
	t := &plannedTarget{
		Path:      l.Path,
		Phase:     phaseStorage,
		Overwrite: cutil.IsTrue(l.Overwrite),
		Node:      &l.Node,
	}
	if hard {
		t.Kind = kindHardlink
		targetPath, err := s.JoinPath(*l.Target)
		if err != nil {
			return nil, fmt.Errorf("error resolving target path of hard link %s: %v", l.Path, err)
		}
		t.LinkTarget = targetPath
	} else {
		t.Kind = targetTypeSymlink
		t.LinkTarget = *l.Target
	}

	existing, err := captureIdentity(l.Path, false)
	if err != nil {
		return nil, err
	}
	t.Original = existing
	if !t.Overwrite && existing.Exists &&
		!p.targetPlanned(phaseStorage, t.Kind, l.Path) {
		if hard {
			if existing.Type != targetTypeFile {
				return nil, fmt.Errorf("error creating hard link %s: a non-file already exists at that path and overwrite is false", l.Path)
			}
			st, err := os.Lstat(l.Path)
			if err != nil {
				return nil, err
			}
			targetst, err := os.Lstat(t.LinkTarget)
			if err != nil {
				return nil, fmt.Errorf("error creating hard link %s: target does not exist or stat() returned an err: %v", l.Path, err)
			}
			if !os.SameFile(st, targetst) {
				return nil, fmt.Errorf("error creating hard link %s: a file already exists at that path but is not the target and overwrite is false", l.Path)
			}
		} else if existing.Type == targetTypeSymlink {
			target, err := os.Readlink(l.Path)
			if err != nil {
				return nil, fmt.Errorf("error reading link at %s: %v", l.Path, err)
			}
			if filepath.Clean(target) != filepath.Clean(*l.Target) {
				return nil, fmt.Errorf("error creating symlink %s: a symlink exists at that path but points to %s, not %s and overwrite is false", l.Path, target, *l.Target)
			}
		} else {
			return nil, fmt.Errorf("error creating symlink %s: a non-symlink already exists at that path and overwrite is false", l.Path)
		}
	}
	p.addTarget(t)
	return t, nil
}

// buildPlan assembles the complete target/record manifest for a config.
func (s *stage) buildPlan(config types.Config, p *filesPlan) error {
	if err := s.buildStoragePlan(config, p); err != nil {
		return err
	}
	if err := s.buildPasswdPlan(config, p); err != nil {
		return err
	}
	if err := s.buildUnitsPlan(config, p); err != nil {
		return err
	}
	if !p.isApply {
		if err := s.buildLuksPlan(config, p); err != nil {
			return err
		}
		if err := s.buildProviderPlan(p); err != nil {
			return err
		}
	}
	// The previous checkpoint has been fully folded into the fresh
	// manifest.
	p.prev = nil
	return nil
}

// buildStoragePlan reproduces the ordering and conflict detection of
// getOrderedCreationList while pinning identities.
func (s *stage) buildStoragePlan(config types.Config, p *filesPlan) error {
	var ordered []*plannedTarget
	var hardlinks []*plannedTarget
	paths := map[string]string{}

	for _, d := range config.Storage.Directories {
		path, err := s.JoinPath(d.Path)
		if err != nil {
			return err
		}
		if existing, ok := paths[path]; ok {
			return fmt.Errorf("directory at %s resolved to %s after symlink chasing, but another entry with path %s also resolves there",
				d.Path, path, existing)
		}
		paths[path] = d.Path
		d.Path = path
		t, err := s.addDirectoryTarget(p, d)
		if err != nil {
			return err
		}
		ordered = append(ordered, t)
	}

	for _, f := range config.Storage.Files {
		path, err := s.JoinPath(f.Path)
		if err != nil {
			return err
		}
		if existing, ok := paths[path]; ok {
			return fmt.Errorf("file at %s resolved to %s after symlink chasing, but another entry with path %s also resolves there",
				f.Path, path, existing)
		}
		paths[path] = f.Path
		f.Path = path
		t, err := s.addFileTarget(p, f, phaseStorage, "file")
		if err != nil {
			return err
		}
		ordered = append(ordered, t)
	}

	for _, l := range config.Storage.Links {
		path, err := s.JoinPath(l.Path)
		if err != nil {
			return err
		}
		if existing, ok := paths[path]; ok {
			return fmt.Errorf("link at %s resolved to %s after symlink chasing, but another entry with path %s also resolves there",
				l.Path, path, existing)
		}
		paths[path] = l.Path
		l.Path = path
		t, err := s.addLinkTarget(p, l)
		if err != nil {
			return err
		}
		if t.Kind == kindHardlink {
			hardlinks = append(hardlinks, t)
		} else {
			ordered = append(ordered, t)
		}
	}

	sort.SliceStable(ordered, func(i, j int) bool {
		return util.Depth(ordered[i].Path) < util.Depth(ordered[j].Path)
	})

	// Reorder the freshly built storage targets: shallow to deep, with
	// hard links last. Non-storage targets follow unchanged.
	storageKeys := make(map[string]bool, len(ordered)+len(hardlinks))
	reordered := make([]*plannedTarget, 0, len(p.cp.Targets))
	for _, t := range ordered {
		storageKeys[targetKey(t)] = true
		reordered = append(reordered, t)
	}
	for _, t := range hardlinks {
		storageKeys[targetKey(t)] = true
		reordered = append(reordered, t)
	}
	for _, t := range p.cp.Targets {
		if !storageKeys[targetKey(t)] {
			reordered = append(reordered, t)
		}
	}
	p.cp.Targets = reordered
	return nil
}

// buildPasswdPlan records the configured groups and users without
// touching anything.
func (s *stage) buildPasswdPlan(config types.Config, p *filesPlan) error {
	for _, g := range config.Passwd.Groups {
		p.groupRecord(g.Name)
	}
	for _, u := range config.Passwd.Users {
		p.userRecord(u.Name)
	}
	return nil
}

// fetchOpToFile turns a FetchOp holding a data: URL into a types.File.
func fetchOpToFile(op util.FetchOp) types.File {
	src := op.Url.String()
	return types.File{
		Node: types.Node{Path: op.Node.Path},
		FileEmbedded1: types.FileEmbedded1{
			Contents: types.Resource{Source: &src},
		},
	}
}

// buildUnitsPlan converts units, dropins, mask/unmask operations and
// presets into planned targets and records.
func (s *stage) buildUnitsPlan(config types.Config, p *filesPlan) error {
	presets := make(map[string]presetRecord)
	for _, unit := range config.Systemd.Units {
		for _, dropin := range unit.Dropins {
			if dropin.Contents == nil {
				continue
			}
			op, err := s.FileFromSystemdUnitDropin(unit, dropin)
			if err != nil {
				s.Crit("error converting systemd dropin: %v", err)
				return err
			}
			if _, err := s.addUnitFileTarget(p, fetchOpToFile(op), "dropin"); err != nil {
				return err
			}
		}

		if !cutil.NilOrEmpty(unit.Contents) {
			op, err := s.FileFromSystemdUnit(unit)
			if err != nil {
				s.Crit("error converting unit: %v", err)
				return err
			}
			if _, err := s.addUnitFileTarget(p, fetchOpToFile(op), "unit"); err != nil {
				return err
			}
		}

		if unit.Enabled != nil {
			identifier := "disabled"
			if *unit.Enabled {
				identifier = "enabled"
			}
			if *unit.Enabled && strings.Contains(unit.Name, "@") {
				unitName, instance, err := parseInstanceUnit(unit)
				if err != nil {
					return err
				}
				key := fmt.Sprintf("%s-%s", unitName, identifier)
				if rec, ok := presets[key]; ok {
					instances := append(strings.Fields(strings.TrimPrefix(rec.UnitString, unitName)), instance)
					rec.UnitString = fmt.Sprintf("%s %s", unitName, strings.Join(instances, " "))
					presets[key] = rec
				} else {
					presets[key] = presetRecord{
						Key:          key,
						UnitString:   fmt.Sprintf("%s %s", unitName, instance),
						Enabled:      true,
						Instantiated: true,
					}
				}
			} else {
				key := fmt.Sprintf("%s-%s", unit.Name, identifier)
				if _, ok := presets[unit.Name]; ok {
					return fmt.Errorf("%q key is already present in the presets map", key)
				}
				presets[key] = presetRecord{
					Key:        key,
					UnitString: unit.Name,
					Enabled:    *unit.Enabled,
				}
			}
		}

		if cutil.IsTrue(unit.Mask) {
			path, err := s.JoinPath(util.SystemdUnitsPath(), unit.Name)
			if err != nil {
				return err
			}
			t := &plannedTarget{
				Path:       path,
				Kind:       kindMask,
				Phase:      phaseUnit,
				LinkTarget: "/dev/null",
				Label:      "mask",
			}
			if t.Original, err = captureIdentity(path, false); err != nil {
				return err
			}
			// A unit contents target at the same path precedes this.
			if other := p.findTarget(phaseUnit, targetTypeFile, path); other != nil {
				t.Chained = true
			}
			p.addTarget(t)
		} else if cutil.IsFalse(unit.Mask) {
			path, err := s.JoinPath(util.SystemdUnitsPath(), unit.Name)
			if err != nil {
				return err
			}
			t := &plannedTarget{
				Path:  path,
				Kind:  kindUnmask,
				Phase: phaseUnit,
				Label: "unmask",
			}
			if t.Original, err = captureIdentity(path, false); err != nil {
				return err
			}
			p.addTarget(t)
		}
	}

	// Register presets in stable key order.
	keys := make([]string, 0, len(presets))
	for k := range presets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		p.addPreset(presets[k])
	}
	return nil
}

// addUnitFileTarget registers a unit/dropin file target.  Unit files
// are replaced wholesale (the unit or dropin explicitly carries
// contents) and land with the default 0644 mode.
func (s *stage) addUnitFileTarget(p *filesPlan, f types.File, label string) (*plannedTarget, error) {
	t := &plannedTarget{
		Path:      f.Path,
		Kind:      targetTypeFile,
		Phase:     phaseUnit,
		Overwrite: true,
		Label:     label,
	}
	id, err := captureIdentity(f.Path, false)
	if err != nil {
		return nil, err
	}
	t.Original = id
	ops, err := s.Util.PrepareFetches(s.Logger, f)
	if err != nil {
		return nil, err
	}
	t.ops = ops
	p.addTarget(t)
	return t, nil
}

// fetchAll fetches and verifies every remote object before the sysroot
// is touched, then derives each target's final content checksum.
func (s *stage) fetchAll(p *filesPlan) error {
	if p.cp.FetchDone {
		// A resumed run trusts the checkpoint, but re-fetch any staged
		// object that is missing or corrupt rather than failing outright.
		for _, t := range p.cp.Targets {
			for i, f := range t.Fetches {
				if p.objectOK(f) {
					continue
				}
				if i >= len(t.ops) {
					return fmt.Errorf("staged content for %q is missing and cannot be re-fetched", t.Path)
				}
				s.Warning("re-fetching missing staged object for %q", t.Path)
				data, err := s.fetchObject(p, t.ops[i])
				if err != nil {
					return err
				}
				name, err := p.storeObject(data)
				if err != nil {
					return err
				}
				t.Fetches[i] = stagedFetch{Obj: name, Append: f.Append, Sum: hashBytes(data)}
			}
			if t.Kind == targetTypeFile {
				if err := s.finalizeFileTarget(p, t); err != nil {
					return err
				}
			}
		}
		return p.save()
	}

	for _, t := range p.cp.Targets {
		if t.Confirmed {
			continue
		}
		for _, op := range t.ops {
			data, err := s.fetchObject(p, op)
			if err != nil {
				return err
			}
			name, err := p.storeObject(data)
			if err != nil {
				return err
			}
			t.Fetches = append(t.Fetches, stagedFetch{
				Obj:    name,
				Append: op.Append,
				Sum:    hashBytes(data),
			})
		}
		if t.Kind == targetTypeFile {
			if err := s.finalizeFileTarget(p, t); err != nil {
				return err
			}
		}
	}

	p.cp.FetchDone = true
	return p.save()
}

// fetchObject retrieves one fetch operation into memory, performing any
// configured hash verification and decompression.
func (s *stage) fetchObject(p *filesPlan, op util.FetchOp) ([]byte, error) {
	tmp, err := os.CreateTemp(p.objectsDir, ".fetch-")
	if err != nil {
		return nil, err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()

	if err := s.Fetcher.Fetch(op.Url, tmp, op.FetchOptions); err != nil {
		s.Crit("Error fetching file %q: %v", op.Node.Path, err)
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	return os.ReadFile(tmpName)
}

// finalizeFileTarget composes the final ordered content of a file target
// from its optional existing prefix and fetched objects and records the
// expected final checksum.
func (s *stage) finalizeFileTarget(p *filesPlan, t *plannedTarget) error {
	h := sha256.New()

	if t.PrefixObj != "" {
		data, err := p.readObject(t.PrefixObj)
		if err != nil {
			return fmt.Errorf("reading staged prefix for %q: %v", t.Path, err)
		}
		if _, err := h.Write(data); err != nil {
			return err
		}
	}

	createdContent := false
	for _, f := range t.Fetches {
		data, err := p.readObject(f.Obj)
		if err != nil {
			return fmt.Errorf("reading staged content for %q: %v", t.Path, err)
		}
		if _, err := h.Write(data); err != nil {
			return err
		}
		createdContent = true
	}

	switch {
	case createdContent || t.PrefixObj != "":
		t.FinalSum = h.Sum(nil)
	case t.Original != nil && t.Original.Exists:
		// Existing file with no content instructions: leave it alone.
		t.FinalSum = nil
	default:
		// Nonexistent file with no contents: create an empty file.
		t.FinalSum = h.Sum(nil)
	}
	return nil
}

// stagePublishFile builds, fetches and registers a dynamic publication
// target (such as the result file) at publish time.
func (s *stage) stagePublishFile(p *filesPlan, path string, data []byte, mode int) (*plannedTarget, error) {
	uri := dataurl.EncodeBytes(data)
	f := types.File{
		Node: types.Node{
			Path:      path,
			Overwrite: cutil.BoolToPtr(true),
		},
		FileEmbedded1: types.FileEmbedded1{
			Contents: types.Resource{Source: &uri},
			Mode:     cutil.IntToPtr(mode),
		},
	}
	t, err := s.addFileTarget(p, f, phasePublish, "publish")
	if err != nil {
		return nil, err
	}
	for _, op := range t.ops {
		body, err := s.fetchObject(p, op)
		if err != nil {
			return nil, err
		}
		name, err := p.storeObject(body)
		if err != nil {
			return nil, err
		}
		t.Fetches = append(t.Fetches, stagedFetch{Obj: name, Sum: hashBytes(body)})
	}
	if err := s.finalizeFileTarget(p, t); err != nil {
		return nil, err
	}
	return t, nil
}

// bytesEqual compares two checksums.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
