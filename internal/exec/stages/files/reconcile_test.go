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
	"bufio"
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
)

const fakeUserTools = `#!/bin/bash
set -u
cmd=$(basename "$0")
root=""
getval() {
  local want="$1"; shift
  local prev=""
  for a in "$@"; do
    if [ "$prev" = "$want" ]; then echo "$a"; return; fi
    prev="$a"
  done
}
root=$(getval --root "$@")
mkdir -p "$root/etc"
touch "$root/etc/shadow" "$root/etc/gshadow"
[ -n "${FAKE_CMD_LOG:-}" ] && echo "$cmd $*" >> "$FAKE_CMD_LOG"
name="${@: -1}"
gidof() { awk -F: -v n="$1" '$1==n{print $3; exit}' "$root/etc/group"; }
case "$cmd" in
  groupadd)
    gid=$(getval --gid "$@")
    if [ -z "$gid" ]; then
      n=$(cat "$root/.nextgid" 2>/dev/null || echo 10000)
      gid=$n; echo $((n+1)) > "$root/.nextgid"
    fi
    echo "$name:x:$gid:" >> "$root/etc/group" ;;
  groupmod)
    gid=$(getval --gid "$@")
    if [ -n "$gid" ]; then
      tmp=$(mktemp)
      awk -F: -v n="$name" -v g="$gid" 'BEGIN{OFS=":"}{if($1==n)$3=g}1' "$root/etc/group" > "$tmp" && mv "$tmp" "$root/etc/group"
    fi ;;
  groupdel)
    sed -i "/^$name:/d" "$root/etc/group" ;;
  useradd)
    uid=$(getval --uid "$@")
    [ -z "$uid" ] && uid=2000
    pg=$(getval --gid "$@"); g=1000; [ -n "$pg" ] && g=$(gidof "$pg")
    home=$(getval --home-dir "$@"); [ -z "$home" ] && home="/home/$name"
    pw=$(getval --password "$@"); [ -z "$pw" ] && pw="*"
    groups=$(getval --groups "$@")
    # INTENTIONAL PARTIAL SUCCESS: --shell is not honored here.
    mkdir -p "$root$home"
    echo "$name:x:$uid:$g::$home:/bin/sh" >> "$root/etc/passwd"
    echo "$name:$pw:::::::" >> "$root/etc/shadow"
    if [ -n "$groups" ]; then
      IFS=',' read -ra gl <<< "$groups"
      for gn in "${gl[@]}"; do
        tmp=$(mktemp)
        awk -F: -v n="$gn" -v u="$name" 'BEGIN{OFS=":"} $1==n { if ($4=="") $4=u; else $4=$4","u } 1' "$root/etc/group" > "$tmp" && mv "$tmp" "$root/etc/group"
      done
    fi ;;
  usermod)
    f_uid=$(getval --uid "$@"); f_gid=$(getval --gid "$@"); f_sh=$(getval --shell "$@")
    f_home=$(getval --home "$@"); f_pw=$(getval --password "$@"); f_groups=$(getval --groups "$@")
    pgid=""; [ -n "$f_gid" ] && pgid=$(gidof "$f_gid")
    tmp=$(mktemp)
    awk -F: -v n="$name" -v uid="$f_uid" -v gid="$pgid" -v sh="$f_sh" -v home="$f_home" 'BEGIN{OFS=":"} $1==n{if(uid!="")$3=uid;if(gid!="")$4=gid;if(sh!="")$7=sh;if(home!="")$6=home}1' "$root/etc/passwd" > "$tmp" && mv "$tmp" "$root/etc/passwd"
    if [ -n "$f_pw" ]; then
      tmp=$(mktemp)
      awk -F: -v n="$name" -v pw="$f_pw" 'BEGIN{OFS=":"}$1==n{$2=pw}1' "$root/etc/shadow" > "$tmp" && mv "$tmp" "$root/etc/shadow"
    fi
    if [ -n "$f_groups" ]; then
      IFS=',' read -ra gl <<< "$f_groups"
      for gn in "${gl[@]}"; do
        tmp=$(mktemp)
        awk -F: -v n="$gn" -v u="$name" 'BEGIN{OFS=":"} $1==n { if ($4=="") $4=u; else $4=$4","u } 1' "$root/etc/group" > "$tmp" && mv "$tmp" "$root/etc/group"
      done
    fi ;;
  userdel)
    sed -i "/^$name:/d" "$root/etc/passwd" "$root/etc/shadow" ;;
esac
exit 0
`

func stageAt(root, stageDir string) *stage {
	logger := log.New(true)
	return &stage{
		Util: util.Util{
			DestDir: root,
			Logger:  &logger,
			Fetcher: resource.Fetcher{Logger: &logger},
			State:   &state.State{},
		},
	}
}

func installFakeUserTools(t *testing.T, logPath string) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"useradd", "usermod", "userdel", "groupadd", "groupmod", "groupdel"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(fakeUserTools), 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("FAKE_CMD_LOG", logPath)
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	return dir
}

func cmdLogContains(t *testing.T, path, substr string) bool {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Contains(string(data), substr)
}

func cmdLogCount(t *testing.T, path, substr string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), substr) {
			n++
		}
	}
	return n
}

func passwdRecord(t *testing.T, root, name string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, "/etc/passwd"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if fields[0] == name {
			return fields
		}
	}
	t.Fatalf("user %q not found", name)
	return nil
}

func TestReconcileUserPartialSuccess(t *testing.T) {
	root := t.TempDir()
	stageDir := filepath.Join(t.TempDir(), "files-stage")
	t.Setenv("IGNITION_FILES_STAGE_DIR", stageDir)
	logPath := filepath.Join(t.TempDir(), "cmd.log")
	installFakeUserTools(t, logPath)

	cfg := types.Config{
		Passwd: types.Passwd{
			Groups: []types.PasswdGroup{
				{Name: "mygrp", Gid: cutil.IntToPtr(2000)},
				{Name: "wheel", Gid: cutil.IntToPtr(3001)},
			},
			Users: []types.PasswdUser{{
				Name:         "myusr",
				UID:          cutil.IntToPtr(3000),
				PrimaryGroup: cutil.StrToPtr("mygrp"),
				Groups:       []types.Group{"wheel"},
				Shell:        cutil.StrToPtr("/bin/zsh"),
				PasswordHash: cutil.StrToPtr("$6$abc"),
			}},
		},
	}

	run := func() {
		s := stageAt(root, stageDir)
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
		if err := s.applyPasswd(cfg, p); err != nil {
			t.Fatalf("applyPasswd: %v", err)
		}
	}

	run()

	fields := passwdRecord(t, root, "myusr")
	if fields[2] != "3000" || fields[3] != "2000" || fields[6] != "/bin/zsh" {
		t.Fatalf("unexpected passwd record: %v", fields)
	}
	shadow, err := os.ReadFile(filepath.Join(root, "/etc/shadow"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(shadow), "myusr:$6$abc:") {
		t.Fatalf("password hash not set: %q", shadow)
	}
	if !cmdLogContains(t, logPath, "groupadd") {
		t.Error("groupadd was not invoked")
	}
	if !cmdLogContains(t, logPath, "useradd") {
		t.Error("useradd was not invoked")
	}
	if cmdLogContains(t, logPath, "usermod") && cmdLogContains(t, logPath, "--shell /bin/zsh") {
		// missing shell was repaired, as expected
	} else {
		t.Error("missing shell attribute was not repaired")
	}
	// The password hash was confirmed during useradd; usermod must not
	// touch it again.
	data, _ := os.ReadFile(logPath)
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "usermod") && strings.Contains(line, "--password") {
			t.Errorf("password was already confirmed but got set again: %s", line)
		}
	}

	// Membership in wheel was written by the partial useradd.
	groups, err := os.ReadFile(filepath.Join(root, "/etc/group"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(groups), "wheel:x:3001:myusr") {
		t.Fatalf("group membership missing: %q", groups)
	}

	// Resume with a fresh process adopting the checkpoint: nothing to do.
	before := cmdLogCount(t, logPath, "")
	run()
	after := cmdLogCount(t, logPath, "")
	if before != after {
		t.Fatalf("resume invoked %d additional commands", after-before)
	}
}

func TestReconcileExistingUserOnlyChangesSpecifiedAttrs(t *testing.T) {
	root := t.TempDir()
	stageDir := filepath.Join(t.TempDir(), "files-stage")
	t.Setenv("IGNITION_FILES_STAGE_DIR", stageDir)
	logPath := filepath.Join(t.TempDir(), "cmd.log")
	installFakeUserTools(t, logPath)

	if err := os.MkdirAll(filepath.Join(root, "/etc"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "/home/old"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "/etc/passwd"),
		[]byte("old:x:1050:1050::/home/old:/bin/sh\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "/etc/shadow"),
		[]byte("old:!*:::::::\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := types.Config{
		Passwd: types.Passwd{
			Users: []types.PasswdUser{{
				Name:  "old",
				Shell: cutil.StrToPtr("/bin/bash"),
			}},
		},
	}

	s := stageAt(root, stageDir)
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
	if err := s.applyPasswd(cfg, p); err != nil {
		t.Fatalf("applyPasswd: %v", err)
	}

	if cmdLogContains(t, logPath, "useradd") {
		t.Error("useradd invoked for an existing user")
	}
	if !cmdLogContains(t, logPath, "usermod") || !cmdLogContains(t, logPath, "--shell /bin/bash") {
		t.Error("existing user shell was not changed")
	}
	fields := passwdRecord(t, root, "old")
	if fields[6] != "/bin/bash" {
		t.Fatalf("shell = %q", fields[6])
	}
}

// TestRunFileOwnedByCreatedUser verifies the new application order:
// storage entries are written before users exist, but ownership by name
// is still applied after group/user reconciliation.
func TestRunFileOwnedByCreatedUser(t *testing.T) {
	root := t.TempDir()
	stageDir := filepath.Join(t.TempDir(), "files-stage")
	t.Setenv("IGNITION_FILES_STAGE_DIR", stageDir)
	logPath := filepath.Join(t.TempDir(), "cmd.log")
	bin := installFakeUserTools(t, logPath)
	for _, spec := range []struct{ name, body string }{
		{"setfiles", "#!/bin/sh\nexit 0\n"},
		{"is-live-image", "#!/bin/sh\nexit 0\n"},
		{"systemctl", "#!/bin/sh\nexit 0\n"},
	} {
		if err := os.WriteFile(filepath.Join(bin, spec.name), []byte(spec.body), 0755); err != nil {
			t.Fatal(err)
		}
	}
	selinuxLayout(t, root)

	cfg := types.Config{
		Passwd: types.Passwd{
			Groups: []types.PasswdGroup{{Name: "mygrp", Gid: cutil.IntToPtr(2000)}},
			Users: []types.PasswdUser{{
				Name:         "myusr",
				UID:          cutil.IntToPtr(3000),
				PrimaryGroup: cutil.StrToPtr("mygrp"),
			}},
		},
		Storage: types.Storage{
			Files: []types.File{{
				Node: types.Node{
					Path: "/etc/app.conf",
					User: types.NodeUser{Name: cutil.StrToPtr("myusr")},
					Group: types.NodeGroup{Name: cutil.StrToPtr("mygrp")},
				},
				FileEmbedded1: types.FileEmbedded1{
					Contents: types.Resource{Source: dataSource([]byte("x\n"))},
					Mode:     cutil.IntToPtr(0640),
				},
			}},
		},
	}

	s := stageAt(root, stageDir)
	if err := s.Run(cfg); err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	fi, err := os.Lstat(filepath.Join(root, "/etc/app.conf"))
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	if st.Uid != 3000 || st.Gid != 2000 {
		t.Fatalf("ownership = %d:%d, want 3000:2000", st.Uid, st.Gid)
	}
	if fi.Mode().Perm() != 0640 {
		t.Fatalf("mode = %o", fi.Mode().Perm())
	}
}
