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
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

var (
	// ErrTargetModifiedExternally is returned when a target that the
	// in-progress plan has not yet confirmed no longer matches the
	// identity captured when the plan was built.  Ignition fails closed
	// rather than overwriting externally modified content with a stale
	// plan.
	ErrTargetModifiedExternally = errors.New("target modified externally since the plan was built; refusing to overwrite")
)

const (
	targetTypeFile    = "file"
	targetTypeDir     = "dir"
	targetTypeSymlink = "symlink"
	targetTypeOther   = "other"
)

// targetIdentity is the pinned original identity of a planned target,
// captured before any content is applied.  It is also used to verify the
// result of a write once it lands.
type targetIdentity struct {
	// Exists reports whether the target existed when the plan was built.
	Exists bool `json:"exists"`
	// Type is one of the targetType* constants.
	Type string `json:"type"`
	// Mode holds the permission and special bits in unix stat form
	// (the low 07777 bits, e.g. 04755).
	Mode uint32 `json:"mode"`
	Uid  int    `json:"uid"`
	Gid  int    `json:"gid"`
	// LinkTarget is set for symlinks.
	LinkTarget string `json:"linkTarget,omitempty"`
	// ContentSum is the SHA-256 of a regular file's content, when the
	// plan needed to capture it.
	ContentSum []byte `json:"contentSum,omitempty"`
}

// modeType classifies a unix stat mode into one of the targetType*
// constants.
func modeType(mode uint32) string {
	switch mode & unix.S_IFMT {
	case unix.S_IFREG:
		return targetTypeFile
	case unix.S_IFDIR:
		return targetTypeDir
	case unix.S_IFLNK:
		return targetTypeSymlink
	default:
		return targetTypeOther
	}
}

// captureIdentity lstat's path and returns its identity.  A missing path
// yields an identity with Exists set to false and no error.  When
// withContent is true and the target is a regular file, its content
// checksum is recorded as well.
func captureIdentity(path string, withContent bool) (*targetIdentity, error) {
	var st unix.Stat_t
	err := unix.Lstat(path, &st)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &targetIdentity{Exists: false}, nil
		}
		return nil, err
	}

	id := &targetIdentity{
		Exists: true,
		Type:   modeType(st.Mode),
		Mode:   st.Mode & 07777,
		Uid:    int(st.Uid),
		Gid:    int(st.Gid),
	}

	if id.Type == targetTypeSymlink {
		target, err := os.Readlink(path)
		if err != nil {
			return nil, fmt.Errorf("reading symlink %q: %v", path, err)
		}
		id.LinkTarget = target
	}

	if withContent && id.Type == targetTypeFile {
		sum, err := hashRegularFile(path)
		if err != nil {
			return nil, err
		}
		id.ContentSum = sum
	}

	return id, nil
}

// sameIdentity reports whether the two identities agree on the metadata
// that defines a target's identity.  Content checksums are not compared.
func sameIdentity(a, b *targetIdentity) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if a.Exists != b.Exists {
		return false
	}
	if !a.Exists {
		return true
	}
	return a.Type == b.Type &&
		a.Mode == b.Mode &&
		a.Uid == b.Uid &&
		a.Gid == b.Gid &&
		a.LinkTarget == b.LinkTarget
}

// hashBytes returns the SHA-256 checksum of b.
func hashBytes(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// hashRegularFile returns the SHA-256 checksum of the regular file at
// path.  The caller is expected to have established that path is a
// regular file.
func hashRegularFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening %q for hashing: %v", path, err)
	}
	defer func() {
		_ = f.Close()
	}()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, fmt.Errorf("hashing %q: %v", path, err)
	}
	return h.Sum(nil), nil
}

// verifyRegularFileContent reports whether the regular file at path
// contains exactly the bytes matching the given checksum.
func verifyRegularFileContent(path string, wantSum []byte) (bool, error) {
	gotSum, err := hashRegularFile(path)
	if err != nil {
		return false, err
	}
	return bytes.Equal(gotSum, wantSum), nil
}
