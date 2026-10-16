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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/coreos/ignition/v2/config/util"
	"github.com/coreos/ignition/v2/config/v3_7_experimental/types"
	"github.com/coreos/ignition/v2/internal/distro"
)

// readColonFile reads a passwd/group-style colon-delimited database
// under DestDir.  A missing database yields no records.
func (s *stage) readColonFile(rel string) ([][]string, error) {
	path := filepath.Join(s.DestDir, rel)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() {
		_ = f.Close()
	}()

	var records [][]string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		records = append(records, strings.Split(line, ":"))
	}
	return records, scanner.Err()
}

func findRecord(records [][]string, name string) ([]string, bool) {
	for _, r := range records {
		if len(r) > 0 && r[0] == name {
			return r, true
		}
	}
	return nil, false
}

func (s *stage) passwdRecord(name string) ([]string, bool, error) {
	records, err := s.readColonFile("/etc/passwd")
	if err != nil {
		return nil, false, fmt.Errorf("reading passwd: %v", err)
	}
	r, ok := findRecord(records, name)
	return r, ok, nil
}

func (s *stage) groupRecordByName(name string) ([]string, bool, error) {
	records, err := s.readColonFile("/etc/group")
	if err != nil {
		return nil, false, fmt.Errorf("reading group: %v", err)
	}
	r, ok := findRecord(records, name)
	return r, ok, nil
}

// lookupGroupGid resolves a group name to its gid using the sysroot
// /etc/group database.
func (s *stage) lookupGroupGid(name string) (int, error) {
	r, ok, err := s.groupRecordByName(name)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, fmt.Errorf("no such group %q", name)
	}
	gid, err := strconv.Atoi(r[2])
	if err != nil {
		return 0, fmt.Errorf("parsing gid %q of group %q: %v", r[2], name, err)
	}
	return gid, nil
}

func (s *stage) shadowHash(name string) (string, bool, error) {
	records, err := s.readColonFile("/etc/shadow")
	if err != nil {
		return "", false, fmt.Errorf("reading shadow: %v", err)
	}
	r, ok := findRecord(records, name)
	if !ok || len(r) < 2 {
		return "", false, nil
	}
	return r[1], true, nil
}

func (s *stage) gshadowHash(name string) (string, bool, error) {
	records, err := s.readColonFile("/etc/gshadow")
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("reading gshadow: %v", err)
	}
	r, ok := findRecord(records, name)
	if !ok || len(r) < 2 {
		return "", false, nil
	}
	return r[1], true, nil
}

// groupMembership returns the set of supplementary group names the user
// belongs to according to /etc/group.
func (s *stage) groupMembership(user string) (map[string]bool, error) {
	records, err := s.readColonFile("/etc/group")
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, r := range records {
		if len(r) < 4 || r[3] == "" {
			continue
		}
		for _, m := range strings.Split(r[3], ",") {
			if m == user {
				out[r[0]] = true
			}
		}
	}
	return out, nil
}

func (s *stage) runLogged(desc, bin string, args ...string) error {
	if _, err := s.LogCmd(exec.Command(bin, args...), "%s", desc); err != nil {
		return fmt.Errorf("%s: %w", desc, err)
	}
	return nil
}

// reconcileGroups creates, deletes and repairs configured groups one
// attribute at a time.  Each attribute is only touched once its
// confirmation bit is clear.
func (s *stage) reconcileGroups(config types.Config, p *filesPlan) error {
	if len(config.Passwd.Groups) == 0 {
		return nil
	}
	s.PushPrefix("ensureGroups")
	defer s.PopPrefix()

	for _, g := range config.Passwd.Groups {
		rec := p.groupRecord(g.Name)
		shouldExist := !util.IsFalse(g.ShouldExist)

		exists, err := s.CheckIfGroupExists(g)
		if err != nil {
			return err
		}

		if !shouldExist {
			if !rec.Deleted {
				if exists {
					args := []string{"--root", s.DestDir, g.Name}
					if err := s.runLogged(fmt.Sprintf("deleting group %q", g.Name), distro.GroupdelCmd(), args...); err != nil {
						return fmt.Errorf("failed to delete group %q: %v", g.Name, err)
					}
				}
				rec.Deleted = true
				if err := p.save(); err != nil {
					return err
				}
			}
			continue
		}

		if !rec.Ensured {
			if !exists {
				args := []string{"--root", s.DestDir}
				if g.Gid != nil {
					args = append(args, "--gid", strconv.FormatUint(uint64(*g.Gid), 10))
				}
				if util.NotEmpty(g.PasswordHash) {
					args = append(args, "--password", *g.PasswordHash)
				}
				if util.IsTrue(g.System) {
					args = append(args, "--system")
				}
				args = append(args, g.Name)
				if err := s.runLogged(fmt.Sprintf("adding group %q", g.Name), distro.GroupaddCmd(), args...); err != nil {
					return fmt.Errorf("failed to create group %q: %v", g.Name, err)
				}
				if exists, err := s.CheckIfGroupExists(g); err != nil {
					return err
				} else if !exists {
					return fmt.Errorf("groupadd reported success but group %q is missing", g.Name)
				}
			}
			rec.Ensured = true
			if err := p.save(); err != nil {
				return err
			}
		}

		if g.Gid != nil && !rec.Gid {
			r, ok, err := s.groupRecordByName(g.Name)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("group %q missing after creation", g.Name)
			}
			cur, err := strconv.Atoi(r[2])
			if err != nil {
				return fmt.Errorf("parsing gid %q: %v", r[2], err)
			}
			if cur != *g.Gid {
				args := []string{"--root", s.DestDir, "--gid",
					strconv.Itoa(*g.Gid)}
				args = append(args, g.Name)
				if err := s.runLogged(fmt.Sprintf("modifying gid of group %q", g.Name), distro.GroupmodCmd(), args...); err != nil {
					return fmt.Errorf("failed to set gid of group %q: %v", g.Name, err)
				}
				r, ok, err = s.groupRecordByName(g.Name)
				if err != nil {
					return err
				}
				cur, _ = strconv.Atoi(r[2])
				if cur != *g.Gid {
					return fmt.Errorf("group %q gid still %d after modification", g.Name, cur)
				}
			}
			rec.Gid = true
			if err := p.save(); err != nil {
				return err
			}
		}

		if util.NotEmpty(g.PasswordHash) && !rec.Password {
			cur, _, err := s.gshadowHash(g.Name)
			if err != nil {
				return err
			}
			if cur != *g.PasswordHash {
				args := []string{"--root", s.DestDir, "--password", *g.PasswordHash, g.Name}
				if err := s.runLogged(fmt.Sprintf("setting password of group %q", g.Name), distro.GroupmodCmd(), args...); err != nil {
					return fmt.Errorf("failed to set group password %q: %v", g.Name, err)
				}
			}
			// gshadow may not exist at all; treat a successful command
			// (or an already matching hash) as confirmation.
			rec.Password = true
			if err := p.save(); err != nil {
				return err
			}
		}
	}
	return nil
}

// reconcileUsers creates or repairs configured users.  When the
// user-creating command partially succeeds, only attributes that cannot
// be verified are repaired on the next invocation.
func (s *stage) reconcileUsers(config types.Config, p *filesPlan) error {
	if len(config.Passwd.Users) == 0 {
		return nil
	}
	s.PushPrefix("ensureUsers")
	defer s.PopPrefix()

	for _, u := range config.Passwd.Users {
		rec := p.userRecord(u.Name)
		shouldExist := !util.IsFalse(u.ShouldExist)

		exists, err := s.CheckIfUserExists(u)
		if err != nil {
			return err
		}

		if !shouldExist {
			if !rec.Deleted {
				if exists {
					args := []string{"--remove", "--root", s.DestDir, u.Name}
					if err := s.runLogged(fmt.Sprintf("deleting user %q", u.Name), distro.UserdelCmd(), args...); err != nil {
						return fmt.Errorf("failed to delete user %q: %v", u.Name, err)
					}
				}
				rec.Deleted = true
				if err := p.save(); err != nil {
					return err
				}
			}
			continue
		}

		if !rec.Ensured {
			if !exists {
				if err := s.runUserAdd(u); err != nil {
					return err
				}
				if exists, err := s.CheckIfUserExists(u); err != nil {
					return err
				} else if !exists {
					return fmt.Errorf("useradd reported success but user %q is missing", u.Name)
				}
			}
			rec.Ensured = true
			if err := p.save(); err != nil {
				return err
			}
		}

		if err := s.reconcileUserAttrs(u, rec, p); err != nil {
			return err
		}
	}
	return nil
}

// runUserAdd creates a user with the same arguments util.EnsureUser used
// for users that do not yet exist.
func (s *stage) runUserAdd(u types.PasswdUser) error {
	args := []string{"--root", s.DestDir}

	if util.NotEmpty(u.HomeDir) {
		args = append(args, "--home-dir", *u.HomeDir)
	}
	if util.IsTrue(u.NoCreateHome) {
		args = append(args, "--no-create-home")
	} else {
		args = append(args, "--create-home")
	}
	args = appendBoolArg(args, u.NoUserGroup, "--no-user-group")
	args = appendBoolArg(args, u.System, "--system")
	args = appendBoolArg(args, u.NoLogInit, "--no-log-init")

	if u.PasswordHash != nil {
		if *u.PasswordHash != "" {
			args = append(args, "--password", *u.PasswordHash)
		} else {
			args = append(args, "--password", "*")
		}
	} else {
		args = append(args, "--password", "*")
	}

	if u.UID != nil {
		args = append(args, "--uid", strconv.FormatUint(uint64(*u.UID), 10))
	}
	args = appendStringArg(args, "--comment", u.Gecos)
	args = appendStringArg(args, "--gid", u.PrimaryGroup)
	if len(u.Groups) > 0 {
		args = append(args, "--groups", strings.Join(groupNames(u.Groups), ","))
	}
	args = appendStringArg(args, "--shell", u.Shell)
	args = append(args, u.Name)

	return s.runLogged(fmt.Sprintf("creating user %q", u.Name), distro.UseraddCmd(), args...)
}

// reconcileUserAttrs verifies each configured attribute against the
// databases and repairs only those that cannot be confirmed.
func (s *stage) reconcileUserAttrs(u types.PasswdUser, rec *userRecord, p *filesPlan) error {
	r, ok, err := s.passwdRecord(u.Name)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("user %q missing from passwd", u.Name)
	}

	usermod := func(desc string, args ...string) error {
		full := append([]string{"--root", s.DestDir}, args...)
		full = append(full, u.Name)
		return s.runLogged(desc, distro.UsermodCmd(), full...)
	}
	refresh := func() error {
		r, ok, err = s.passwdRecord(u.Name)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("user %q vanished during reconciliation", u.Name)
		}
		return nil
	}

	if u.UID != nil && !rec.UID {
		cur, err := strconv.Atoi(r[2])
		if err != nil {
			return fmt.Errorf("parsing uid %q for %q: %v", r[2], u.Name, err)
		}
		if cur != *u.UID {
			if err := usermod(fmt.Sprintf("setting uid of user %q", u.Name),
				"--uid", strconv.Itoa(*u.UID)); err != nil {
				return fmt.Errorf("failed to set uid for %q: %v", u.Name, err)
			}
			if err := refresh(); err != nil {
				return err
			}
			cur, _ = strconv.Atoi(r[2])
			if cur != *u.UID {
				return fmt.Errorf("user %q uid still %d after modification", u.Name, cur)
			}
		}
		rec.UID = true
		if err := p.save(); err != nil {
			return err
		}
	}

	if util.NotEmpty(u.PrimaryGroup) && !rec.PrimaryGroup {
		wantGid, err := s.lookupGroupGid(*u.PrimaryGroup)
		if err != nil {
			return err
		}
		cur, err := strconv.Atoi(r[3])
		if err != nil {
			return fmt.Errorf("parsing gid %q for %q: %v", r[3], u.Name, err)
		}
		if cur != wantGid {
			if err := usermod(fmt.Sprintf("setting primary group of user %q", u.Name),
				"--gid", *u.PrimaryGroup); err != nil {
				return fmt.Errorf("failed to set primary group for %q: %v", u.Name, err)
			}
			if err := refresh(); err != nil {
				return err
			}
			cur, _ = strconv.Atoi(r[3])
			if cur != wantGid {
				return fmt.Errorf("user %q primary gid still %d after modification", u.Name, cur)
			}
		}
		rec.PrimaryGroup = true
		if err := p.save(); err != nil {
			return err
		}
	}

	if len(u.Groups) > 0 && !rec.Groups {
		want := map[string]bool{}
		for _, g := range groupNames(u.Groups) {
			want[g] = true
		}
		have, err := s.groupMembership(u.Name)
		if err != nil {
			return err
		}
		if !stringSetEqual(want, have) {
			if err := usermod(fmt.Sprintf("setting groups of user %q", u.Name),
				"--groups", strings.Join(groupNames(u.Groups), ",")); err != nil {
				return fmt.Errorf("failed to set groups for %q: %v", u.Name, err)
			}
			have, err = s.groupMembership(u.Name)
			if err != nil {
				return err
			}
			if !stringSetEqual(want, have) {
				return fmt.Errorf("user %q groups still %v after modification", u.Name, have)
			}
		}
		rec.Groups = true
		if err := p.save(); err != nil {
			return err
		}
	}

	if util.NotEmpty(u.Shell) && !rec.Shell {
		if r[6] != *u.Shell {
			if err := usermod(fmt.Sprintf("setting shell of user %q", u.Name),
				"--shell", *u.Shell); err != nil {
				return fmt.Errorf("failed to set shell for %q: %v", u.Name, err)
			}
			if err := refresh(); err != nil {
				return err
			}
			if r[6] != *u.Shell {
				return fmt.Errorf("user %q shell still %q after modification", u.Name, r[6])
			}
		}
		rec.Shell = true
		if err := p.save(); err != nil {
			return err
		}
	}

	if util.NotEmpty(u.Gecos) && !rec.Gecos {
		if r[4] != *u.Gecos {
			if err := usermod(fmt.Sprintf("setting comment of user %q", u.Name),
				"--comment", *u.Gecos); err != nil {
				return fmt.Errorf("failed to set comment for %q: %v", u.Name, err)
			}
			if err := refresh(); err != nil {
				return err
			}
			if r[4] != *u.Gecos {
				return fmt.Errorf("user %q comment still %q after modification", u.Name, r[4])
			}
		}
		rec.Gecos = true
		if err := p.save(); err != nil {
			return err
		}
	}

	if util.NotEmpty(u.HomeDir) && !rec.Home {
		if r[5] != *u.HomeDir {
			// Match the existing behavior of moving an existing home.
			if err := usermod(fmt.Sprintf("moving home directory of user %q", u.Name),
				"--home", *u.HomeDir, "--move-home"); err != nil {
				return fmt.Errorf("failed to set home directory for %q: %v", u.Name, err)
			}
			if err := refresh(); err != nil {
				return err
			}
			if r[5] != *u.HomeDir {
				return fmt.Errorf("user %q home still %q after modification", u.Name, r[5])
			}
		}
		rec.Home = true
		if err := p.save(); err != nil {
			return err
		}
	}

	if u.PasswordHash != nil && !rec.Password {
		want := *u.PasswordHash
		if want == "" {
			want = "*"
		}
		cur, ok, err := s.shadowHash(u.Name)
		if err != nil {
			return err
		}
		if !ok || cur != want {
			if err := usermod(fmt.Sprintf("setting password for user %q", u.Name),
				"--password", want); err != nil {
				return fmt.Errorf("failed to set password for %q: %v", u.Name, err)
			}
			cur, ok, err = s.shadowHash(u.Name)
			if err != nil {
				return err
			}
			if !ok || cur != want {
				return fmt.Errorf("user %q password hash could not be confirmed", u.Name)
			}
		}
		rec.Password = true
		if err := p.save(); err != nil {
			return err
		}
	}

	return nil
}

// finalizeUsers applies home-directory permissions and SSH authorized
// keys after existence and attributes are confirmed.
func (s *stage) finalizeUsers(config types.Config, p *filesPlan) error {
	for _, u := range config.Passwd.Users {
		if util.IsFalse(u.ShouldExist) {
			continue
		}
		rec := p.userRecord(u.Name)

		if !rec.HomePerms {
			if err := s.ModifyHomeDirPermissions(u); err != nil {
				return fmt.Errorf("failed to modify home directory permissions for %q: %v",
					u.Name, err)
			}
			rec.HomePerms = true
			if err := p.save(); err != nil {
				return err
			}
		}

		if len(u.SSHAuthorizedKeys) > 0 && !rec.Keys {
			if err := s.AuthorizeSSHKeys(u); err != nil {
				return fmt.Errorf("failed to add keys to user %q: %v", u.Name, err)
			}
			if err := s.verifyAuthorizedKeys(u); err != nil {
				return err
			}
			rec.Keys = true
			if err := p.save(); err != nil {
				return err
			}
		}
	}
	return nil
}

// verifyAuthorizedKeys confirms the Ignition-managed keys file content.
func (s *stage) verifyAuthorizedKeys(u types.PasswdUser) error {
	homedir, err := s.GetUserHomeDir(u)
	if err != nil {
		return err
	}
	var rel string
	if distro.WriteAuthorizedKeysFragment() {
		rel = filepath.Join(homedir, ".ssh", "authorized_keys.d", "ignition")
	} else {
		rel = filepath.Join(homedir, ".ssh", "authorized_keys")
	}
	path, err := s.JoinPath(rel)
	if err != nil {
		return err
	}
	keys := make([]string, len(u.SSHAuthorizedKeys))
	for i, k := range u.SSHAuthorizedKeys {
		keys[i] = string(k)
	}
	want := strings.Join(keys, "\n")
	if !strings.HasSuffix(want, "\n") {
		want += "\n"
	}
	got, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading authorized keys for %q: %v", u.Name, err)
	}
	if string(got) != want {
		return fmt.Errorf("authorized keys for %q could not be confirmed", u.Name)
	}
	return nil
}

func appendBoolArg(args []string, test *bool, arg string) []string {
	if util.IsTrue(test) {
		return append(args, arg)
	}
	return args
}

func appendStringArg(args []string, arg string, str *string) []string {
	if util.NotEmpty(str) {
		return append(args, arg, *str)
	}
	return args
}

func groupNames(groups []types.Group) []string {
	out := make([]string, len(groups))
	for i, g := range groups {
		out[i] = string(g)
	}
	return out
}

func stringSetEqual(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}
