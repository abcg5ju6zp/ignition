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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	cutil "github.com/coreos/ignition/v2/config/util"
	"github.com/coreos/ignition/v2/config/v3_7_experimental/types"
	"github.com/coreos/ignition/v2/internal/exec/util"
	"github.com/coreos/ignition/v2/internal/log"
	"github.com/coreos/ignition/v2/internal/resource"
	"github.com/coreos/ignition/v2/internal/state"

	"github.com/vincent-petithory/dataurl"
)

func testStage(t *testing.T) (*stage, string) {
	t.Helper()
	root := t.TempDir()
	stageDir := filepath.Join(t.TempDir(), "files-stage")
	t.Setenv("IGNITION_FILES_STAGE_DIR", stageDir)
	logger := log.New(true)
	s := &stage{
		Util: util.Util{
			DestDir: root,
			Logger:  &logger,
			Fetcher: resource.Fetcher{Logger: &logger},
			State:   &state.State{},
		},
	}
	return s, root
}

func dataSource(b []byte) *string {
	s := dataurl.EncodeBytes(b)
	return &s
}

// installFakeTools provides no-op external commands invoked by the stage
// in boot-flow tests.
func installFakeTools(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeExec := func(name, body string) {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0755); err != nil {
			t.Fatal(err)
		}
	}
	writeExec("setfiles", "#!/bin/sh\nexit 0\n")
	writeExec("is-live-image", "#!/bin/sh\nexit 0\n")
	writeExec("systemctl", `#!/bin/sh
case "$3" in
is-enabled) exit 1 ;;
*) exit 0 ;;
esac
`)
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	return dir
}

func selinuxLayout(t *testing.T, root string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, "/etc/selinux/targeted/contexts/files"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "/etc/selinux/config"),
		[]byte("SELINUXTYPE=targeted\n"), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestConfigGeneration(t *testing.T) {
	cfg := types.Config{}
	g1, err := configGeneration(cfg, "/root")
	if err != nil {
		t.Fatal(err)
	}
	g2, err := configGeneration(cfg, "/root")
	if err != nil {
		t.Fatal(err)
	}
	if g1 != g2 {
		t.Fatalf("generation digest not stable: %q vs %q", g1, g2)
	}
	g3, _ := configGeneration(types.Config{Ignition: types.Ignition{Version: "3.7.0"}}, "/root")
	if g1 == g3 {
		t.Fatal("generation digest did not change with the config")
	}
	g4, _ := configGeneration(cfg, "/other")
	if g1 == g4 {
		t.Fatal("generation digest did not change with the root")
	}
}

func TestIdentityCapture(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "f")
	if err := os.WriteFile(path, []byte("hello"), 0640); err != nil {
		t.Fatal(err)
	}
	id, err := captureIdentity(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if !id.Exists || id.Type != targetTypeFile {
		t.Fatalf("unexpected identity: %+v", id)
	}
	if id.Mode != 0640 {
		t.Fatalf("mode = %o, want 0640", id.Mode)
	}
	if want := hashBytes([]byte("hello")); !bytesEqual(id.ContentSum, want) {
		t.Fatal("content checksum mismatch")
	}

	link := filepath.Join(root, "l")
	if err := os.Symlink("f", link); err != nil {
		t.Fatal(err)
	}
	lid, err := captureIdentity(link, false)
	if err != nil {
		t.Fatal(err)
	}
	if lid.Type != targetTypeSymlink || lid.LinkTarget != "f" {
		t.Fatalf("unexpected link identity: %+v", lid)
	}

	missing, err := captureIdentity(filepath.Join(root, "missing"), false)
	if err != nil {
		t.Fatal(err)
	}
	if missing.Exists {
		t.Fatal("missing path reported as existing")
	}
}

func TestFetchFailureTouchesNothing(t *testing.T) {
	s, root := testStage(t)
	bad := "badscheme:x"
	cfg := types.Config{
		Storage: types.Storage{
			Files: []types.File{{
				Node: types.Node{Path: "/nope"},
				FileEmbedded1: types.FileEmbedded1{
					Contents: types.Resource{Source: &bad},
				},
			}},
		},
	}
	err := s.Run(cfg)
	if err == nil {
		t.Fatal("expected fetch failure")
	}
	if _, err := os.Lstat(filepath.Join(root, "nope")); !os.IsNotExist(err) {
		t.Fatalf("file was created despite fetch failure: %v", err)
	}
}

func TestRunCreatesEntries(t *testing.T) {
	s, root := testStage(t)
	installFakeTools(t)
	selinuxLayout(t, root)

	cfg := types.Config{
		Storage: types.Storage{
			Directories: []types.Directory{{
				Node: types.Node{Path: "/etc/custom"},
				DirectoryEmbedded1: types.DirectoryEmbedded1{
					Mode: cutil.IntToPtr(0700),
				},
			}},
			Files: []types.File{{
				Node: types.Node{Path: "/etc/custom/hello"},
				FileEmbedded1: types.FileEmbedded1{
					Contents: types.Resource{Source: dataSource([]byte("hello\n"))},
					Mode:     cutil.IntToPtr(0600),
				},
			}},
			Links: []types.Link{{
				Node: types.Node{Path: "/etc/custom/link"},
				LinkEmbedded1: types.LinkEmbedded1{
					Target: cutil.StrToPtr("hello"),
				},
			}},
		},
	}
	if err := s.Run(cfg); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	body, err := os.ReadFile(filepath.Join(root, "/etc/custom/hello"))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "hello\n" {
		t.Fatalf("content = %q", body)
	}
	if fi, err := os.Lstat(filepath.Join(root, "/etc/custom/hello")); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0600 {
		t.Fatalf("file mode = %o", fi.Mode().Perm())
	}
	if fi, err := os.Lstat(filepath.Join(root, "/etc/custom")); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0700 {
		t.Fatalf("dir mode = %o", fi.Mode().Perm())
	}
	target, err := os.Readlink(filepath.Join(root, "/etc/custom/link"))
	if err != nil {
		t.Fatal(err)
	}
	if target != "hello" {
		t.Fatalf("symlink target = %q", target)
	}

	// Successful completion removes the stage state.
	if _, err := os.Lstat(os.Getenv("IGNITION_FILES_STAGE_DIR")); !os.IsNotExist(err) {
		t.Fatalf("stage directory was not cleaned up: %v", err)
	}
}

func TestExternalModificationRefused(t *testing.T) {
	s, root := testStage(t)

	original := []byte("ORIGINAL\n")
	if err := os.MkdirAll(filepath.Join(root, "/etc"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "/etc/log"), original, 0644); err != nil {
		t.Fatal(err)
	}

	cfg := types.Config{
		Storage: types.Storage{
			Files: []types.File{{
				Node: types.Node{Path: "/etc/log"},
				FileEmbedded1: types.FileEmbedded1{
					Append: []types.Resource{{Source: dataSource([]byte("EXTRA\n"))}},
				},
			}},
		},
	}

	p, err := s.initPlan(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.buildPlan(cfg, p); err != nil {
		t.Fatal(err)
	}
	if err := s.fetchAll(p); err != nil {
		t.Fatal(err)
	}

	// Somebody else changes the target after the plan was pinned.
	if err := os.WriteFile(filepath.Join(root, "/etc/log"), []byte("TAMPERED\n"), 0644); err != nil {
		t.Fatal(err)
	}

	err = s.applyTargets(p, phaseStorage)
	if !errors.Is(err, ErrTargetModifiedExternally) {
		t.Fatalf("expected ErrTargetModifiedExternally, got %v", err)
	}
	body, _ := os.ReadFile(filepath.Join(root, "/etc/log"))
	if string(body) != "TAMPERED\n" {
		t.Fatalf("tampered content was modified: %q", body)
	}
}

func TestAlreadyDesiredAdopted(t *testing.T) {
	s, root := testStage(t)

	cfg := types.Config{
		Storage: types.Storage{
			Files: []types.File{{
				Node: types.Node{Path: "/new"},
				FileEmbedded1: types.FileEmbedded1{
					Contents: types.Resource{Source: dataSource([]byte("done"))},
				},
			}},
		},
	}

	p, err := s.initPlan(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.buildPlan(cfg, p); err != nil {
		t.Fatal(err)
	}
	if err := s.fetchAll(p); err != nil {
		t.Fatal(err)
	}

	// A previous interrupted invocation (or the admin) already wrote the
	// exact planned content.
	if err := os.WriteFile(filepath.Join(root, "new"), []byte("done"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := s.applyTargets(p, phaseStorage); err != nil {
		t.Fatalf("expected adoption of desired state: %v", err)
	}
	target := p.findTarget(phaseStorage, targetTypeFile, filepath.Join(root, "new"))
	if target == nil || !target.Confirmed {
		t.Fatal("target was not marked confirmed")
	}
}

func TestAppendAtomicResume(t *testing.T) {
	root := t.TempDir()
	stageDir := filepath.Join(t.TempDir(), "files-stage")
	t.Setenv("IGNITION_FILES_STAGE_DIR", stageDir)

	build := func() (*stage, types.Config) {
		logger := log.New(true)
		s := &stage{
			Util: util.Util{
				DestDir: root,
				Logger:  &logger,
				Fetcher: resource.Fetcher{Logger: &logger},
				State:   &state.State{},
			},
		}
		cfg := types.Config{
			Storage: types.Storage{
				Files: []types.File{{
					Node: types.Node{Path: "/appended"},
					FileEmbedded1: types.FileEmbedded1{
						Append: []types.Resource{{Source: dataSource([]byte("B"))}},
					},
				}},
			},
		}
		return s, cfg
	}

	if err := os.WriteFile(filepath.Join(root, "appended"), []byte("A"), 0644); err != nil {
		t.Fatal(err)
	}

	s1, cfg := build()
	p1, err := s1.initPlan(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.buildPlan(cfg, p1); err != nil {
		t.Fatal(err)
	}
	if err := s1.fetchAll(p1); err != nil {
		t.Fatal(err)
	}
	if err := s1.applyTargets(p1, phaseStorage); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(filepath.Join(root, "appended"))
	if string(body) != "AB" {
		t.Fatalf("content = %q, want AB", body)
	}

	// Simulate a process exit and a fresh invocation resuming the plan.
	s2, _ := build()
	p2, err := s2.initPlan(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.buildPlan(cfg, p2); err != nil {
		t.Fatal(err)
	}
	if err := s2.fetchAll(p2); err != nil {
		t.Fatal(err)
	}
	if err := s2.applyTargets(p2, phaseStorage); err != nil {
		t.Fatalf("resume failed: %v", err)
	}
	body, _ = os.ReadFile(filepath.Join(root, "appended"))
	if string(body) != "AB" {
		t.Fatalf("resume duplicated content: %q, want AB", body)
	}
}

func TestEmptyBootRunPublishesResult(t *testing.T) {
	s, root := testStage(t)
	installFakeTools(t)
	selinuxLayout(t, root)

	if err := s.Run(types.Config{}); err != nil {
		t.Fatalf("empty Run failed: %v", err)
	}
	fi, err := os.Lstat(filepath.Join(root, "/etc/.ignition-result.json"))
	if err != nil {
		t.Fatalf("result file missing: %v", err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("result mode = %o", fi.Mode().Perm())
	}
	if _, err := os.Lstat(os.Getenv("IGNITION_FILES_STAGE_DIR")); !os.IsNotExist(err) {
		t.Fatal("checkpoint directory left behind after completion")
	}
}

func TestOverwriteReplacesNonRegular(t *testing.T) {
	s, root := testStage(t)
	installFakeTools(t)
	selinuxLayout(t, root)

	// Pre-existing directory at the target path.
	if err := os.MkdirAll(filepath.Join(root, "/victim/nested"), 0755); err != nil {
		t.Fatal(err)
	}
	cfg := types.Config{
		Storage: types.Storage{
			Files: []types.File{{
				Node: types.Node{
					Path:      "/victim",
					Overwrite: cutil.BoolToPtr(true),
				},
				FileEmbedded1: types.FileEmbedded1{
					Contents: types.Resource{Source: dataSource([]byte("x"))},
					Mode:     cutil.IntToPtr(0644),
				},
			}},
		},
	}
	if err := s.Run(cfg); err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	fi, err := os.Lstat(filepath.Join(root, "victim"))
	if err != nil {
		t.Fatal(err)
	}
	if !fi.Mode().IsRegular() {
		t.Fatalf("target not replaced by regular file: %v", fi.Mode())
	}
}

func TestMaskUnmaskIdempotent(t *testing.T) {
	s, root := testStage(t)
	installFakeTools(t)
	selinuxLayout(t, root)

	cfg := types.Config{
		Systemd: types.Systemd{
			Units: []types.Unit{{
				Name:     "masked.service",
				Contents: cutil.StrToPtr("[Service]\nExecStart=/bin/true\n"),
				Mask:     cutil.BoolToPtr(true),
			}},
		},
	}
	if err := s.Run(cfg); err != nil {
		t.Fatalf("mask run failed: %v", err)
	}
	maskPath := filepath.Join(root, util.SystemdUnitsPath(), "masked.service")
	target, err := os.Readlink(maskPath)
	if err != nil {
		t.Fatalf("unit not masked: %v", err)
	}
	if target != "/dev/null" {
		t.Fatalf("mask target = %q", target)
	}

	// Running the same plan again must stay masked and succeed.
	s2, _ := testStage(t)
	s2.Util.DestDir = root
	if err := s2.Run(cfg); err != nil {
		t.Fatalf("second mask run failed: %v", err)
	}
	if target, err := os.Readlink(maskPath); err != nil || target != "/dev/null" {
		t.Fatalf("unit not masked after rerun: %q %v", target, err)
	}

	// Unmask.
	unmask := types.Config{
		Systemd: types.Systemd{
			Units: []types.Unit{{
				Name: "masked.service",
				Mask: cutil.BoolToPtr(false),
			}},
		},
	}
	s3, _ := testStage(t)
	s3.Util.DestDir = root
	if err := s3.Run(unmask); err != nil {
		t.Fatalf("unmask run failed: %v", err)
	}
	if _, err := os.Lstat(maskPath); !os.IsNotExist(err) {
		t.Fatalf("unit still present after unmask: %v", err)
	}
}

func TestPresetPublishedAndResumed(t *testing.T) {
	s, root := testStage(t)
	installFakeTools(t)
	selinuxLayout(t, root)

	cfg := types.Config{
		Systemd: types.Systemd{
			Units: []types.Unit{{
				Name:    "foo.service",
				Enabled: cutil.BoolToPtr(true),
			}},
		},
	}
	if err := s.Run(cfg); err != nil {
		t.Fatalf("run failed: %v", err)
	}
	preset, err := os.ReadFile(filepath.Join(root, util.PresetPath))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(preset), "enable foo.service") != 1 {
		t.Fatalf("preset content unexpected:\n%s", preset)
	}
}

func TestAppendPreservesIdentity(t *testing.T) {
	s, root := testStage(t)
	installFakeTools(t)
	selinuxLayout(t, root)

	path := filepath.Join(root, "kept")
	if err := os.WriteFile(path, []byte("A"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 42, 43); err != nil {
		t.Fatal(err)
	}

	cfg := types.Config{
		Storage: types.Storage{
			Files: []types.File{{
				Node: types.Node{Path: "/kept"},
				FileEmbedded1: types.FileEmbedded1{
					Append: []types.Resource{{Source: dataSource([]byte("B"))}},
				},
			}},
		},
	}
	if err := s.Run(cfg); err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "AB" {
		t.Fatalf("content = %q", body)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	if st.Uid != 42 || st.Gid != 43 {
		t.Fatalf("ownership = %d:%d, want 42:43", st.Uid, st.Gid)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("mode = %o", fi.Mode().Perm())
	}
}

func TestRelabelFailureKeepsResumeAndDelaysPublication(t *testing.T) {
	root := t.TempDir()
	stageDir := filepath.Join(t.TempDir(), "files-stage")
	t.Setenv("IGNITION_FILES_STAGE_DIR", stageDir)

	bin := t.TempDir()
	marker := filepath.Join(t.TempDir(), "failed")
	setfiles := "#!/bin/sh\nif [ ! -f " + marker + " ]; then\n  touch " + marker + "\n  exit 1\nfi\nexit 0\n"
	for _, spec := range []struct{ name, body string }{
		{"setfiles", setfiles},
		{"is-live-image", "#!/bin/sh\nexit 0\n"},
		{"systemctl", "#!/bin/sh\nexit 0\n"},
	} {
		if err := os.WriteFile(filepath.Join(bin, spec.name), []byte(spec.body), 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	selinuxLayout(t, root)

	cfg := types.Config{
		Storage: types.Storage{
			Files: []types.File{{
				Node: types.Node{Path: "/f"},
				FileEmbedded1: types.FileEmbedded1{
					Contents: types.Resource{Source: dataSource([]byte("data"))},
					Mode:     cutil.IntToPtr(0644),
				},
			}},
		},
	}

	s1 := stageAt(root, stageDir)
	if err := s1.Run(cfg); err == nil {
		t.Fatal("first run should fail at relabel")
	}
	if _, err := os.Stat(filepath.Join(root, "/etc/.ignition-result.json")); !os.IsNotExist(err) {
		t.Fatal("result published before content was confirmed/relabeled")
	}
	if _, err := os.Stat(filepath.Join(stageDir, "checkpoint.json")); err != nil {
		t.Fatalf("checkpoint not preserved for resume: %v", err)
	}

	s2 := stageAt(root, stageDir)
	if err := s2.Run(cfg); err != nil {
		t.Fatalf("resumed run failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "/etc/.ignition-result.json")); err != nil {
		t.Fatalf("result not published on resume: %v", err)
	}
	if _, err := os.Stat(stageDir); !os.IsNotExist(err) {
		t.Fatal("stage directory not cleaned up after completion")
	}
}

// TestPublishRelabelFailureResume fails setfiles only on the second
// invocation (the publish relabel), verifying presets/result are not
// rewritten or duplicated on resume and the final relabel is retried.
func TestPublishRelabelFailureResume(t *testing.T) {
	root := t.TempDir()
	stageDir := filepath.Join(t.TempDir(), "files-stage")
	t.Setenv("IGNITION_FILES_STAGE_DIR", stageDir)

	bin := t.TempDir()
	marker := filepath.Join(t.TempDir(), "calls")
	setfiles := `#!/bin/sh
n=$(cat "` + marker + `" 2>/dev/null || echo 0)
n=$((n+1)); echo $n > "` + marker + `"
if [ "$n" = "2" ]; then exit 1; fi
exit 0
`
	for _, spec := range []struct{ name, body string }{
		{"setfiles", setfiles},
		{"is-live-image", "#!/bin/sh\nexit 0\n"},
		{"systemctl", "#!/bin/sh\nexit 0\n"},
	} {
		if err := os.WriteFile(filepath.Join(bin, spec.name), []byte(spec.body), 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	selinuxLayout(t, root)

	cfg := types.Config{
		Storage: types.Storage{
			Files: []types.File{{
				Node: types.Node{Path: "/f"},
				FileEmbedded1: types.FileEmbedded1{
					Contents: types.Resource{Source: dataSource([]byte("data"))},
					Mode:     cutil.IntToPtr(0644),
				},
			}},
		},
		Systemd: types.Systemd{
			Units: []types.Unit{{
				Name:    "foo.service",
				Enabled: cutil.BoolToPtr(true),
			}},
		},
	}

	s1 := stageAt(root, stageDir)
	if err := s1.Run(cfg); err == nil {
		t.Fatal("first run should fail at publish relabel")
	}
	preset, err := os.ReadFile(filepath.Join(root, util.PresetPath))
	if err != nil {
		t.Fatalf("preset should have been published: %v", err)
	}

	s2 := stageAt(root, stageDir)
	if err := s2.Run(cfg); err != nil {
		t.Fatalf("resumed run failed: %v", err)
	}
	preset2, err := os.ReadFile(filepath.Join(root, util.PresetPath))
	if err != nil {
		t.Fatal(err)
	}
	if string(preset) != string(preset2) {
		t.Fatalf("preset was rewritten on resume:\n%s\n%s", preset, preset2)
	}
	if strings.Count(string(preset2), "enable foo.service") != 1 {
		t.Fatalf("preset line duplicated: %q", preset2)
	}
	if _, err := os.Stat(stageDir); !os.IsNotExist(err) {
		t.Fatal("stage directory left behind after completion")
	}
}
