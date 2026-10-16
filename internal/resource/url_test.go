// Copyright 2020 Red Hat, Inc.
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

package resource

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha512"
	stderrors "errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/coreos/ignition/v2/config/shared/errors"
	"github.com/coreos/ignition/v2/internal/log"
	"github.com/coreos/ignition/v2/internal/util"
)

func TestDataUrl(t *testing.T) {
	type in struct {
		url  string
		opts FetchOptions
	}
	type out struct {
		data []byte
		err  error
	}

	tests := []struct {
		in  in
		out out
	}{
		// data url, no compression
		{
			in: in{
				url: "data:,hello%20world%0a",
				opts: FetchOptions{
					ExpectedSum: []byte("\xdb\x39\x74\xa9\x7f\x24\x07\xb7\xca\xe1\xae\x63\x7c\x00\x30\x68\x7a\x11\x91\x32\x74\xd5\x78\x49\x25\x58\xe3\x9c\x16\xc0\x17\xde\x84\xea\xcd\xc8\xc6\x2f\xe3\x4e\xe4\xe1\x2b\x4b\x14\x28\x81\x7f\x09\xb6\xa2\x76\x0c\x3f\x8a\x66\x4c\xea\xe9\x4d\x24\x34\xa5\x93"),
				},
			},
			out: out{data: []byte("hello world\n")},
		},
		// data url, bad hash
		{
			in: in{
				url: "data:,hello%20world%0a",
				opts: FetchOptions{
					ExpectedSum: []byte("\xdb\x39\x74\xa9\x7f\x24\x07\xb7\xca\xe1\xae\x63\x7c\x00\x30\x68\x7a\x11\x91\x32\x74\xd5\x78\x49\x25\x58\xe3\x9c\x16\xc0\x17\xde\x84\xea\xcd\xc8\xc6\x2f\xe3\x4e\xe4\xe1\x2b\x4b\x14\x28\x81\x7f\x09\xb6\xa2\x76\x0c\x3f\x8a\x66\x4c\xea\xe9\x4d\x24\x34\xa5\x00"),
				},
			},
			out: out{err: util.ErrHashMismatch{
				Calculated: "db3974a97f2407b7cae1ae637c0030687a11913274d578492558e39c16c017de84eacdc8c62fe34ee4e12b4b1428817f09b6a2760c3f8a664ceae94d2434a593",
				Expected:   "db3974a97f2407b7cae1ae637c0030687a11913274d578492558e39c16c017de84eacdc8c62fe34ee4e12b4b1428817f09b6a2760c3f8a664ceae94d2434a500",
			}},
		},
		// data url, gzipped
		{
			in: in{
				url: "data:,%1F%8B%08%08%90e%AB%5E%02%03z%00K%ADH%CC-%C8IUH%CB%CCI%E5%02%00tp%A6%CB%0D%00%00%00",
				opts: FetchOptions{
					Compression: "gzip",
					// digest of decompressed data
					ExpectedSum: []byte("\x80\x7e\x8f\xf9\x49\xe6\x1d\x23\xf5\xee\x42\xa6\x29\xec\x96\xe9\xfc\x52\x6b\x62\xf0\x30\xcd\x70\xba\x2c\xd5\xb9\xd9\x79\x35\x46\x1e\xac\xc2\x9b\xf5\x8b\xcd\x04\x26\xe9\xe1\xfd\xb0\xed\xa9\x39\x60\x3e\xd5\x2c\x9c\x06\xd0\x71\x22\x08\xa1\x5c\xd5\x82\xc6\x0e"),
				},
			},
			out: out{data: []byte("example file\n")},
		},
		// data url, gzipped, bad hash
		{
			in: in{
				url: "data:,%1F%8B%08%08%90e%AB%5E%02%03z%00K%ADH%CC-%C8IUH%CB%CCI%E5%02%00tp%A6%CB%0D%00%00%00",
				opts: FetchOptions{
					Compression: "gzip",
					ExpectedSum: []byte("\x80\x7e\x8f\xf9\x49\xe6\x1d\x23\xf5\xee\x42\xa6\x29\xec\x96\xe9\xfc\x52\x6b\x62\xf0\x30\xcd\x70\xba\x2c\xd5\xb9\xd9\x79\x35\x46\x1e\xac\xc2\x9b\xf5\x8b\xcd\x04\x26\xe9\xe1\xfd\xb0\xed\xa9\x39\x60\x3e\xd5\x2c\x9c\x06\xd0\x71\x22\x08\xa1\x5c\xd5\x82\xc6\x00"),
				},
			},
			out: out{err: util.ErrHashMismatch{
				Calculated: "807e8ff949e61d23f5ee42a629ec96e9fc526b62f030cd70ba2cd5b9d97935461eacc29bf58bcd0426e9e1fdb0eda939603ed52c9c06d0712208a15cd582c60e",
				Expected:   "807e8ff949e61d23f5ee42a629ec96e9fc526b62f030cd70ba2cd5b9d97935461eacc29bf58bcd0426e9e1fdb0eda939603ed52c9c06d0712208a15cd582c600",
			}},
		},
		// data url, invalid compressed data
		{
			in: in{
				url: "data:,hello%20world%0a",
				opts: FetchOptions{
					Compression: "gzip",
				},
			},
			out: out{err: gzip.ErrHeader},
		},
		// data url, bad compression type
		{
			in: in{
				url: "data:,hello%20world%0a",
				opts: FetchOptions{
					Compression: "xor",
				},
			},
			out: out{err: errors.ErrCompressionInvalid},
		},
	}

	logger := log.New(true)
	f := Fetcher{
		Logger: &logger,
	}

	for i, test := range tests {
		u, err := url.Parse(test.in.url)
		if err != nil {
			t.Errorf("#%d: parsing URL: %v", i, err)
			continue
		}
		test.in.opts.Hash = sha512.New()
		result, err := f.FetchToBuffer(*u, test.in.opts)
		if !reflect.DeepEqual(test.out.err, err) {
			t.Errorf("#%d: fetching URL: expected error %+v, got %+v", i, test.out.err, err)
			continue
		}
		if test.out.err == nil && !reflect.DeepEqual(test.out.data, result) {
			t.Errorf("#%d: expected output %+v, got %+v", i, test.out.data, result)
			continue
		}
	}
}

func TestFetchOffline(t *testing.T) {
	type in struct {
		url  string
		opts FetchOptions
	}
	type out struct {
		data []byte
		err  error
	}

	tests := []struct {
		in  in
		out out
	}{
		// data url, no compression
		{
			in: in{
				url: "data:,hello%20world%0a",
				opts: FetchOptions{
					ExpectedSum: []byte("\xdb\x39\x74\xa9\x7f\x24\x07\xb7\xca\xe1\xae\x63\x7c\x00\x30\x68\x7a\x11\x91\x32\x74\xd5\x78\x49\x25\x58\xe3\x9c\x16\xc0\x17\xde\x84\xea\xcd\xc8\xc6\x2f\xe3\x4e\xe4\xe1\x2b\x4b\x14\x28\x81\x7f\x09\xb6\xa2\x76\x0c\x3f\x8a\x66\x4c\xea\xe9\x4d\x24\x34\xa5\x93"),
				},
			},
			out: out{data: []byte("hello world\n")},
		},
		// empty
		{
			in: in{
				url: "",
			},
			out: out{data: nil},
		},
		// http url
		{
			in: in{
				url: "http://google.com",
			},
			out: out{err: ErrNeedNet},
		},
		// https url
		{
			in: in{
				url: "https://google.com",
			},
			out: out{err: ErrNeedNet},
		},
		// tftp url
		{
			in: in{
				url: "tftp://127.0.0.1/tftp",
			},
			out: out{err: ErrNeedNet},
		},
		// s3 url
		{
			in: in{
				url: "s3://kola-fixtures/resources/anonymous",
			},
			out: out{err: ErrNeedNet},
		},
		// arn url specifying bucket
		{
			in: in{
				url: "arn:aws:s3:::kola-fixtures/resources/anonymous",
			},
			out: out{err: ErrNeedNet},
		},
		// arn url specifying s3 access point
		{
			in: in{
				url: "arn:aws:s3:us-west-2:123456789012:accesspoint/test/object/name",
			},
			out: out{err: ErrNeedNet},
		},
		// gs url
		{
			in: in{
				url: "gs://foo/bar",
			},
			out: out{err: ErrNeedNet},
		},
	}

	logger := log.New(true)
	f := Fetcher{
		Logger:  &logger,
		Offline: true,
	}

	for i, test := range tests {
		u, err := url.Parse(test.in.url)
		if err != nil {
			t.Errorf("#%d: parsing URL: %v", i, err)
			continue
		}
		test.in.opts.Hash = sha512.New()
		result, err := f.FetchToBuffer(*u, test.in.opts)
		if !reflect.DeepEqual(test.out.err, err) {
			t.Errorf("#%d: fetching URL: expected error %+v, got %+v", i, test.out.err, err)
			continue
		}
		if test.out.err == nil && !reflect.DeepEqual(test.out.data, result) {
			t.Errorf("#%d: expected output %+v, got %+v", i, test.out.data, result)
			continue
		}
	}
}

func TestParseARN(t *testing.T) {
	tests := []struct {
		url        string
		bucket     string
		key        string
		region     string
		regionHint string
		err        error
	}{
		{
			url: "arn:aws:iam:us-west-2:123456789012:resource",
			err: errors.ErrInvalidS3ARN,
		},
		{
			url: "arn:aws:s3:us-east-1:123456789012:accesspoint/test/object",
			err: errors.ErrInvalidS3ARN,
		},
		{
			url: "arn:aws:s3:us-east-1:123456789012:accesspoint/test/name",
			err: errors.ErrInvalidS3ARN,
		},
		{
			url:        "arn:aws:s3:::kola-fixtures/resources/anonymous",
			bucket:     "kola-fixtures",
			key:        "resources/anonymous",
			regionHint: "us-east-1",
		},
		{
			url:        "arn:aws-cn:s3:::kola-fixtures/resources/anonymous",
			bucket:     "kola-fixtures",
			key:        "resources/anonymous",
			regionHint: "cn-north-1",
		},
		{
			url:        "arn:aws-us-gov:s3:::kola-fixtures/resources/anonymous",
			bucket:     "kola-fixtures",
			key:        "resources/anonymous",
			regionHint: "us-gov-west-1",
		},
		{
			url:    "arn:invalid:s3:::kola-fixtures/resources/anonymous",
			bucket: "kola-fixtures",
			key:    "resources/anonymous",
		},
		{
			url:        "arn:aws:s3:us-west-2:123456789012:accesspoint/test/object/name",
			bucket:     "arn:aws:s3:us-west-2:123456789012:accesspoint/test",
			key:        "name",
			region:     "us-west-2",
			regionHint: "us-east-1",
		},
		{
			url:        "arn:aws-cn:s3:cn-northwest-1:123456789012:accesspoint/test/object/name",
			bucket:     "arn:aws-cn:s3:cn-northwest-1:123456789012:accesspoint/test",
			key:        "name",
			region:     "cn-northwest-1",
			regionHint: "cn-north-1",
		},
		{
			url:        "arn:aws-us-gov:s3:us-gov-east-1:123456789012:accesspoint/test/object/name",
			bucket:     "arn:aws-us-gov:s3:us-gov-east-1:123456789012:accesspoint/test",
			key:        "name",
			region:     "us-gov-east-1",
			regionHint: "us-gov-west-1",
		},
		{
			url:    "arn:invalid:s3:us-west-2:123456789012:accesspoint/test/object/name",
			bucket: "arn:invalid:s3:us-west-2:123456789012:accesspoint/test",
			key:    "name",
			region: "us-west-2",
		},
		{
			url:        "arn:aws:s3:us-west-2:123456789012:accesspoint/test/object/path/object",
			bucket:     "arn:aws:s3:us-west-2:123456789012:accesspoint/test",
			key:        "path/object",
			region:     "us-west-2",
			regionHint: "us-east-1",
		},
	}

	logger := log.New(true)
	f := Fetcher{
		Logger: &logger,
	}

	for i, test := range tests {
		bucket, key, region, regionHint, err := f.parseARN(test.url)
		assert.Equal(t, test.err, err, "#%d: bad err", i)
		assert.Equal(t, test.bucket, bucket, "#%d: bad bucket", i)
		assert.Equal(t, test.key, key, "#%d: bad key", i)
		assert.Equal(t, test.region, region, "#%d: bad region", i)
		assert.Equal(t, test.regionHint, regionHint, "#%d: bad region hint", i)
	}
}

func TestParseAzureStorageUrl(t *testing.T) {
	tests := []struct {
		url            url.URL
		storageAccount string
		container      string
		file           string
		err            error
	}{
		{
			url: url.URL{
				Scheme: "https",
				Host:   "example.blob.core.windows.net",
				Path:   "/my-container/file.ign",
			},
			storageAccount: "https://example.blob.core.windows.net/",
			container:      "my-container",
			file:           "file.ign",
			err:            nil,
		},
		{
			url: url.URL{
				Scheme: "https",
				Host:   "example.blob.core.windows.net",
				Path:   "/invalid-url",
			},
			storageAccount: "",
			container:      "",
			file:           "",
			err:            fmt.Errorf("invalid URL path, ensure url has a structure of /container/filename.ign: /invalid-url"),
		},
		{
			url: url.URL{
				Scheme: "https",
				Host:   "example.blob.core.windows.net",
				Path:   "/invalid-url/another-blob/myfile.ign",
			},
			storageAccount: "",
			container:      "",
			file:           "",
			err:            fmt.Errorf("invalid URL path, ensure url has a structure of /container/filename.ign: /invalid-url/another-blob/myfile.ign"),
		},
	}

	logger := log.New(true)
	f := Fetcher{
		Logger: &logger,
	}
	for i, test := range tests {
		storageAccount, container, file, err := f.parseAzureStorageUrl(test.url)
		assert.Equal(t, test.err, err, "#%d: bad err", i)
		assert.Equal(t, test.storageAccount, storageAccount, "#%d: bad storageAccount", i)
		assert.Equal(t, test.container, container, "#%d: bad container", i)
		assert.Equal(t, test.file, file, "#%d: bad file", i)
	}

}

func TestGCSURLConstruction(t *testing.T) {
	tests := []struct {
		name     string
		gsURL    string
		wantPath string
	}{
		{
			name:     "simple object",
			gsURL:    "gs://my-bucket/my-object.ign",
			wantPath: "/storage/v1/b/my-bucket/o/my-object.ign",
		},
		{
			name:     "nested path",
			gsURL:    "gs://my-bucket/path/to/config.ign",
			wantPath: "/storage/v1/b/my-bucket/o/path%2Fto%2Fconfig.ign",
		},
		{
			name:     "object with spaces",
			gsURL:    "gs://my-bucket/my file.ign",
			wantPath: "/storage/v1/b/my-bucket/o/my%20file.ign",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			u, err := url.Parse(test.gsURL)
			assert.NoError(t, err)

			bucket := u.Host
			object := u.Path[1:]
			gcsURL := url.URL{
				Scheme:   "https",
				Host:     "storage.googleapis.com",
				Path:     fmt.Sprintf("/storage/v1/b/%s/o/%s", bucket, url.PathEscape(object)),
				RawQuery: "alt=media",
			}
			assert.Equal(t, test.wantPath, gcsURL.Path)
			assert.Equal(t, "alt=media", gcsURL.RawQuery)
		})
	}
}

func TestFetchFromGCSIntegration(t *testing.T) {
	tests := []struct {
		name        string
		bucket      string
		object      string
		tokenSource oauth2.TokenSource
		body        string
		wantAuth    string
	}{
		{
			name:     "anonymous fetch",
			bucket:   "my-bucket",
			object:   "config.ign",
			body:     `{"ignition":{"version":"3.4.0"}}`,
			wantAuth: "",
		},
		{
			name:   "authenticated fetch",
			bucket: "my-bucket",
			object: "config.ign",
			body:   `{"ignition":{"version":"3.4.0"}}`,
			tokenSource: oauth2.StaticTokenSource(&oauth2.Token{
				AccessToken: "test-token",
				TokenType:   "Bearer",
			}),
			wantAuth: "Bearer test-token",
		},
		{
			name:     "object with slashes",
			bucket:   "my-bucket",
			object:   "path/to/config.ign",
			body:     "nested-content",
			wantAuth: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var gotAuth string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotAuth = r.Header.Get("Authorization")

				wantPath := fmt.Sprintf("/storage/v1/b/%s/o/%s",
					test.bucket, url.PathEscape(test.object))
				gotPath := r.URL.RawPath
				if gotPath == "" {
					gotPath = r.URL.Path
				}
				assert.Equal(t, wantPath, gotPath, "bad request path")
				assert.Equal(t, "media", r.URL.Query().Get("alt"), "missing alt=media")

				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()

			serverURL, _ := url.Parse(server.URL)

			logger := log.New(true)
			f := Fetcher{
				Logger:         &logger,
				GCSTokenSource: test.tokenSource,
			}

			decodedPath := fmt.Sprintf("/storage/v1/b/%s/o/%s", test.bucket, test.object)
			rawPath := fmt.Sprintf("/storage/v1/b/%s/o/%s", test.bucket, url.PathEscape(test.object))
			gcsURL := url.URL{
				Scheme:   serverURL.Scheme,
				Host:     serverURL.Host,
				Path:     decodedPath,
				RawPath:  rawPath,
				RawQuery: "alt=media",
			}

			opts := FetchOptions{
				Headers: make(http.Header),
			}
			if f.GCSTokenSource != nil {
				token, err := f.GCSTokenSource.Token()
				assert.NoError(t, err)
				opts.Headers.Set("Authorization", token.Type()+" "+token.AccessToken)
			}

			dest := new(bytes.Buffer)
			err := f.fetchFromHTTP(gcsURL, dest, opts)
			assert.NoError(t, err)
			assert.Equal(t, test.body, dest.String(), "bad response body")
			assert.Equal(t, test.wantAuth, gotAuth, "bad auth header")
		})
	}
}

func TestFetchConfigDualStack(t *testing.T) {
	logger := log.New(true)
	f := Fetcher{
		Logger: &logger,
	}

	tests := []struct {
		name         string
		userdataURLs map[string]url.URL
		fetchConfig  func(*Fetcher, url.URL) ([]byte, error)
		expectError  bool
		expectIPv    string
	}{
		{
			name: "IPv4 only success",
			userdataURLs: map[string]url.URL{
				IPv4: {
					Scheme: "data",
					Opaque: "," + url.PathEscape(`{"ignition":{"version":"3.5.0"},"storage":{}}`),
				},
			},
			fetchConfig: func(f *Fetcher, u url.URL) ([]byte, error) {
				return f.FetchToBuffer(u, FetchOptions{})
			},
			expectError: false,
			expectIPv:   IPv4,
		},
		{
			name: "IPv6 only success",
			userdataURLs: map[string]url.URL{
				IPv6: {
					Scheme: "data",
					Opaque: "," + url.PathEscape(`{"ignition":{"version":"3.5.0"},"storage":{}}`),
				},
			},
			fetchConfig: func(f *Fetcher, u url.URL) ([]byte, error) {
				return f.FetchToBuffer(u, FetchOptions{})
			},
			expectError: false,
			expectIPv:   IPv6,
		},
		{
			name: "both IPv4 and IPv6 success",
			userdataURLs: map[string]url.URL{
				IPv4: {
					Scheme: "data",
					Opaque: "," + url.PathEscape(`{"ignition":{"version":"3.5.0"},"storage":{}}`),
				},
				IPv6: {
					Scheme: "data",
					Opaque: "," + url.PathEscape(`{"ignition":{"version":"3.5.0"},"passwd":{"users":[{"name":"test"}]}}`),
				},
			},
			fetchConfig: func(f *Fetcher, u url.URL) ([]byte, error) {
				return f.FetchToBuffer(u, FetchOptions{})
			},
			expectError: false,
		},
		{
			name: "both IPv4 and IPv6 fail - use invalid JSON to avoid network retries",
			userdataURLs: map[string]url.URL{
				IPv4: {
					Scheme: "data",
					Opaque: ",invalid-json-content",
				},
				IPv6: {
					Scheme: "data",
					Opaque: ",also-invalid-json",
				},
			},
			fetchConfig: func(f *Fetcher, u url.URL) ([]byte, error) {
				return f.FetchToBuffer(u, FetchOptions{})
			},
			expectError: true,
		},

		{
			name: "IPv4 success with invalid JSON",
			userdataURLs: map[string]url.URL{
				IPv4: {
					Scheme: "data",
					Opaque: ",invalid-json",
				},
			},
			fetchConfig: func(f *Fetcher, u url.URL) ([]byte, error) {
				return f.FetchToBuffer(u, FetchOptions{})
			},
			expectError: true,
		},
		{
			name: "IPv4 fails, IPv6 succeeds",
			userdataURLs: map[string]url.URL{
				IPv4: {
					Scheme: "data",
					Opaque: ",invalid-json",
				},
				IPv6: {
					Scheme: "data",
					Opaque: "," + url.PathEscape(`{"ignition":{"version":"3.5.0"},"storage":{}}`),
				},
			},
			fetchConfig: func(f *Fetcher, u url.URL) ([]byte, error) {
				return f.FetchToBuffer(u, FetchOptions{})
			},
			expectError: false,
			expectIPv:   IPv6,
		},
		{
			name: "IPv4 returns empty data",
			userdataURLs: map[string]url.URL{
				IPv4: {
					Scheme: "data",
					Opaque: ",",
				},
			},
			fetchConfig: func(f *Fetcher, u url.URL) ([]byte, error) {
				// Return empty bytes to simulate empty metadata response
				return []byte{}, nil
			},
			expectError: true,
		},
	}

	for i, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg, rpt, err := FetchConfigDualStack(&f, test.userdataURLs, test.fetchConfig)

			if test.expectError {
				if err == nil {
					t.Errorf("#%d: FetchConfigDualStack() expected error, got nil", i)
				}
				// For empty data case, verify it returns ErrEmpty
				if test.name == "IPv4 returns empty data" && err != errors.ErrEmpty {
					t.Errorf("#%d: FetchConfigDualStack() expected errors.ErrEmpty for empty data, got %v", i, err)
				}
				// Config should be empty on error
				if cfg.Ignition.Version != "" {
					t.Errorf("#%d: FetchConfigDualStack() should return empty config on error, got version %q", i, cfg.Ignition.Version)
				}
			} else {
				if err != nil {
					t.Errorf("#%d: FetchConfigDualStack() unexpected error: %v", i, err)
				}
				// Should have a valid config
				if cfg.Ignition.Version == "" {
					t.Errorf("#%d: FetchConfigDualStack() should return non-zero config for valid URLs", i)
				}
			}

			_ = rpt
		})
	}
}

// Minimal fail-fast assertion helpers; testify/require is not vendored.

func reqNoError(t testing.TB, err error, msg ...any) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v %s", err, fmt.Sprint(msg...))
	}
}

func reqError(t testing.TB, err error, msg ...any) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error %s", fmt.Sprint(msg...))
	}
}

func reqErrorIs(t testing.TB, err, target error) {
	t.Helper()
	if !stderrors.Is(err, target) {
		t.Fatalf("expected error %v, got %v", target, err)
	}
}

func reqErrorAs(t testing.TB, err error, target any) {
	t.Helper()
	if !stderrors.As(err, target) {
		t.Fatalf("expected error of type %T, got %v", target, err)
	}
}

func reqEqual[T any](t testing.TB, want, got T, msg ...any) {
	t.Helper()
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("not equal: want %#v, got %#v %s", want, got, fmt.Sprint(msg...))
	}
}

func reqNil(t testing.TB, v any, msg ...any) {
	t.Helper()
	if v == nil {
		return
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Ptr, reflect.Interface, reflect.Slice, reflect.Map, reflect.Chan, reflect.Func:
		if rv.IsNil() {
			return
		}
	}
	t.Fatalf("expected nil, got %#v %s", v, fmt.Sprint(msg...))
}

func reqEmpty(t testing.TB, v []byte, msg ...any) {
	t.Helper()
	if len(v) != 0 {
		t.Fatalf("expected empty, got %#v %s", v, fmt.Sprint(msg...))
	}
}

func reqElementsMatch[T any](t testing.TB, want, got []T, msg ...any) {
	t.Helper()
	if !assert.ElementsMatch(t, want, got, msg...) {
		t.FailNow()
	}
}

var (
	errPrimaryInterrupt  = stderrors.New("primary attempt interrupted mid-stream")
	errSecondaryFails    = stderrors.New("fallback attempt failed too")
	errSimulatedIMDSRole = stderrors.New("failed to retrieve EC2 IMDS role credentials: simulated")
)

// failingReader returns data bytes followed by err, simulating a download
// which writes part of its object before the connection breaks.
type failingReader struct {
	data []byte
	err  error
}

func (r *failingReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

// failingBody is an http.Response.Body which yields a prefix of the object
// and then an error, modelling a credentialed download dying mid-object.
type failingBody struct {
	data []byte
	err  error
}

func (b *failingBody) Read(p []byte) (int, error) {
	if len(b.data) == 0 {
		return 0, b.err
	}
	n := copy(p, b.data)
	b.data = b.data[n:]
	return n, nil
}

func (b *failingBody) Close() error { return nil }

func gzipEncode(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, err := zw.Write(data)
	reqNoError(t, err)
	reqNoError(t, zw.Close())
	return buf.Bytes()
}

func newCandidateFetcher(t *testing.T) Fetcher {
	t.Helper()
	logger := log.New(true)
	return Fetcher{Logger: &logger}
}

func candidateTempFiles(t *testing.T) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(os.TempDir(), fetchCandidatePrefix+"*"))
	reqNoError(t, err)
	return matches
}

// TestFetchToBufferWithFallbackCandidates verifies that, in memory, each
// authentication/protocol attempt owns an independent candidate: bytes and
// hash state from an interrupted primary attempt can never be continued by
// the fallback, only the fully read/decompressed/verified winner is handed
// back, and failures return no partial contents.
func TestFetchToBufferWithFallbackCandidates(t *testing.T) {
	winner := []byte("winner contents\n")
	winnerSum := sha512.Sum512(winner)
	validGzip := gzipEncode(t, winner)
	truncatedGzip := truncatedGzipOf(validGzip)

	tests := []struct {
		name     string
		opts     func() FetchOptions
		attempts []func(f *Fetcher, opts FetchOptions) fetchCandidateFunc
		expect   []byte
		// expectErrIs matches sentinel or wrapped errors.
		expectErrIs []error
		// expectHashMismatch asserts a digest verification failure.
		expectHashMismatch bool
	}{
		{
			name: "credentialed stream interrupted, anonymous fallback wins",
			opts: func() FetchOptions {
				return FetchOptions{Hash: sha512.New(), ExpectedSum: winnerSum[:]}
			},
			attempts: []func(f *Fetcher, opts FetchOptions) fetchCandidateFunc{
				func(f *Fetcher, opts FetchOptions) fetchCandidateFunc {
					return func(w io.Writer) error {
						return f.decompressCopyHashAndVerify(w,
							&failingReader{data: []byte("GARBAGE-PRIMARY-PREFIX"), err: errPrimaryInterrupt}, opts)
					}
				},
				func(f *Fetcher, opts FetchOptions) fetchCandidateFunc {
					return func(w io.Writer) error {
						return f.decompressCopyHashAndVerify(w, bytes.NewReader(winner), opts)
					}
				},
			},
			expect: winner,
		},
		{
			name: "both attempts fail returns the last error and no bytes",
			opts: func() FetchOptions { return FetchOptions{} },
			attempts: []func(f *Fetcher, opts FetchOptions) fetchCandidateFunc{
				func(f *Fetcher, opts FetchOptions) fetchCandidateFunc {
					return func(w io.Writer) error {
						_, _ = w.Write([]byte("primary partial"))
						return errPrimaryInterrupt
					}
				},
				func(f *Fetcher, opts FetchOptions) fetchCandidateFunc {
					return func(w io.Writer) error {
						_, _ = w.Write([]byte("fallback partial"))
						return errSecondaryFails
					}
				},
			},
			expectErrIs: []error{errSecondaryFails},
		},
		{
			name: "complete download but digest mismatch rejects candidate",
			opts: func() FetchOptions {
				badSum := make([]byte, sha512.Size)
				badSum[0] = 0xff
				return FetchOptions{Hash: sha512.New(), ExpectedSum: badSum}
			},
			attempts: []func(f *Fetcher, opts FetchOptions) fetchCandidateFunc{
				func(f *Fetcher, opts FetchOptions) fetchCandidateFunc {
					return func(w io.Writer) error {
						return f.decompressCopyHashAndVerify(w, bytes.NewReader(winner), opts)
					}
				},
			},
			expectHashMismatch: true,
		},
		{
			name: "truncated gzip primary discarded, valid gzip fallback wins",
			opts: func() FetchOptions {
				return FetchOptions{
					Compression: "gzip",
					Hash:        sha512.New(),
					ExpectedSum: winnerSum[:],
				}
			},
			attempts: []func(f *Fetcher, opts FetchOptions) fetchCandidateFunc{
				func(f *Fetcher, opts FetchOptions) fetchCandidateFunc {
					return func(w io.Writer) error {
						return f.decompressCopyHashAndVerify(w,
							bytes.NewReader(truncatedGzip), opts)
					}
				},
				func(f *Fetcher, opts FetchOptions) fetchCandidateFunc {
					return func(w io.Writer) error {
						return f.decompressCopyHashAndVerify(w,
							bytes.NewReader(validGzip), opts)
					}
				},
			},
			expect: winner,
		},
		{
			name: "invalid gzip stream is rejected with its own error",
			opts: func() FetchOptions {
				return FetchOptions{Compression: "gzip"}
			},
			attempts: []func(f *Fetcher, opts FetchOptions) fetchCandidateFunc{
				func(f *Fetcher, opts FetchOptions) fetchCandidateFunc {
					return func(w io.Writer) error {
						return f.decompressCopyHashAndVerify(w,
							bytes.NewReader([]byte("plain text, not gzip")), opts)
					}
				},
			},
			expectErrIs: []error{gzip.ErrHeader},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newCandidateFetcher(t)
			opts := test.opts()
			attempts := make([]fetchCandidateFunc, 0, len(test.attempts))
			for _, build := range test.attempts {
				attempts = append(attempts, build(&f, opts))
			}
			data, err := f.fetchToBufferWithFallback(attempts)
			if test.expectHashMismatch {
				var mismatch util.ErrHashMismatch
				reqErrorAs(t, err, &mismatch)
			} else if len(test.expectErrIs) > 0 {
				reqError(t, err)
				for _, target := range test.expectErrIs {
					reqErrorIs(t, err, target)
				}
			} else {
				reqNoError(t, err)
			}
			if test.expectHashMismatch || len(test.expectErrIs) > 0 {
				reqNil(t, data, "no partial contents may be observed on error")
				return
			}
			reqEqual(t, test.expect, data)
		})
	}
}

// truncatedGzipOf returns a truncated copy of a valid gzip stream
// which begins to inflate and then fails in the middle of the stream, so some
// decompressed bytes reach the candidate before the error.
func truncatedGzipOf(gz []byte) []byte {
	return gz[:len(gz)-8]
}

// TestFetchToFileWithFallbackCandidates is the file-backed counterpart: each
// attempt streams into a private temporary candidate, and only the verified
// winner is published into the caller's destination. Failed candidates and
// their file offsets never reach either a later attempt or the destination,
// candidates are removed, and an error leaves the destination empty.
func TestFetchToFileWithFallbackCandidates(t *testing.T) {
	winner := []byte("winner contents written to a file\n")
	winnerSum := sha512.Sum512(winner)
	validGzip := gzipEncode(t, winner)
	truncatedGzip := truncatedGzipOf(validGzip)

	before := candidateTempFiles(t)

	t.Run("credentialed stream interrupted, fallback published atomically", func(t *testing.T) {
		f := newCandidateFetcher(t)
		dest, err := os.CreateTemp("", "ignition-test-dest-*")
		reqNoError(t, err)
		defer func() { _ = os.Remove(dest.Name()) }()
		defer func() { _ = dest.Close() }()

		opts := FetchOptions{Hash: sha512.New(), ExpectedSum: winnerSum[:]}
		err = f.fetchToFileWithFallback(dest, []fetchCandidateFunc{
			func(w io.Writer) error {
				return f.decompressCopyHashAndVerify(w,
					&failingReader{data: []byte("GARBAGE-PRIMARY-PREFIX"), err: errPrimaryInterrupt}, opts)
			},
			func(w io.Writer) error {
				return f.decompressCopyHashAndVerify(w, bytes.NewReader(winner), opts)
			},
		})
		reqNoError(t, err)

		got, err := os.ReadFile(dest.Name())
		reqNoError(t, err)
		reqEqual(t, winner, got, "destination must contain exactly the winning attempt")
	})

	t.Run("both attempts fail leaves destination empty and removes candidates", func(t *testing.T) {
		f := newCandidateFetcher(t)
		dest, err := os.CreateTemp("", "ignition-test-dest-*")
		reqNoError(t, err)
		defer func() { _ = os.Remove(dest.Name()) }()
		defer func() { _ = dest.Close() }()

		err = f.fetchToFileWithFallback(dest, []fetchCandidateFunc{
			func(w io.Writer) error {
				_, _ = w.Write([]byte("primary partial"))
				return errPrimaryInterrupt
			},
			func(w io.Writer) error {
				_, _ = w.Write([]byte("fallback partial"))
				return errSecondaryFails
			},
		})
		reqErrorIs(t, err, errSecondaryFails)

		got, err := os.ReadFile(dest.Name())
		reqNoError(t, err)
		reqEmpty(t, got, "failed candidates must never reach the destination file")
	})

	t.Run("complete download with bad digest is never published", func(t *testing.T) {
		f := newCandidateFetcher(t)
		dest, err := os.CreateTemp("", "ignition-test-dest-*")
		reqNoError(t, err)
		defer func() { _ = os.Remove(dest.Name()) }()
		defer func() { _ = dest.Close() }()

		badSum := make([]byte, sha512.Size)
		badSum[0] = 0xff
		opts := FetchOptions{Hash: sha512.New(), ExpectedSum: badSum}
		err = f.fetchToFileWithFallback(dest, []fetchCandidateFunc{
			func(w io.Writer) error {
				return f.decompressCopyHashAndVerify(w, bytes.NewReader(winner), opts)
			},
		})
		var mismatch util.ErrHashMismatch
		reqErrorAs(t, err, &mismatch)

		got, err := os.ReadFile(dest.Name())
		reqNoError(t, err)
		reqEmpty(t, got)
	})

	t.Run("publication failure is final and skips later attempts", func(t *testing.T) {
		f := newCandidateFetcher(t)
		dest, err := os.CreateTemp("", "ignition-test-dest-*")
		reqNoError(t, err)
		defer func() { _ = os.Remove(dest.Name()) }()

		secondRan := false
		// Close the destination so publication of the verified winner fails.
		reqNoError(t, dest.Close())
		err = f.fetchToFileWithFallback(dest, []fetchCandidateFunc{
			func(w io.Writer) error {
				_, _ = w.Write(winner)
				return nil
			},
			func(w io.Writer) error {
				secondRan = true
				return nil
			},
		})
		reqError(t, err)
		assert.False(t, secondRan, "no further attempt must run after a verified winner")
	})

	t.Run("truncated gzip primary discarded, valid gzip fallback wins", func(t *testing.T) {
		f := newCandidateFetcher(t)
		dest, err := os.CreateTemp("", "ignition-test-dest-*")
		reqNoError(t, err)
		defer func() { _ = os.Remove(dest.Name()) }()
		defer func() { _ = dest.Close() }()

		opts := FetchOptions{
			Compression: "gzip",
			Hash:        sha512.New(),
			ExpectedSum: winnerSum[:],
		}
		err = f.fetchToFileWithFallback(dest, []fetchCandidateFunc{
			func(w io.Writer) error {
				return f.decompressCopyHashAndVerify(w, bytes.NewReader(truncatedGzip), opts)
			},
			func(w io.Writer) error {
				return f.decompressCopyHashAndVerify(w, bytes.NewReader(validGzip), opts)
			},
		})
		reqNoError(t, err)

		got, err := os.ReadFile(dest.Name())
		reqNoError(t, err)
		reqEqual(t, winner, got)
	})

	after := candidateTempFiles(t)
	reqElementsMatch(t, before, after, "temporary candidate files leaked")
}

// TestPlainHTTPSingleAttemptKeepsSemantics makes sure a non-Azure HTTP(S) URL
// still performs a single direct fetch (custom headers, digest, file and
// buffer destinations) through the new attempt wiring.
func TestPlainHTTPSingleAttemptKeepsSemantics(t *testing.T) {
	payload := []byte("plain http object\n")
	sum := sha512.Sum512(payload)

	var gotHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Ignition-Test")
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		_, _ = w.Write(payload)
	}))
	defer server.Close()

	u, err := url.Parse(server.URL + "/object")
	reqNoError(t, err)

	opts := FetchOptions{
		Hash:        sha512.New(),
		ExpectedSum: sum[:],
		Headers:     http.Header{"X-Ignition-Test": []string{"candidate"}},
	}

	f := newCandidateFetcher(t)

	data, err := f.FetchToBuffer(*u, opts)
	reqNoError(t, err)
	reqEqual(t, payload, data)
	reqEqual(t, "candidate", gotHeader)

	dest, err := os.CreateTemp("", "ignition-test-dest-*")
	reqNoError(t, err)
	defer func() { _ = os.Remove(dest.Name()) }()
	defer func() { _ = dest.Close() }()

	reqNoError(t, f.Fetch(*u, dest, opts))
	got, err := os.ReadFile(dest.Name())
	reqNoError(t, err)
	reqEqual(t, payload, got)
}

// testCredentialsProvider is a static aws.CredentialsProvider used to make
// the authenticated S3 client produce signed requests.
type testCredentialsProvider struct{}

func (testCredentialsProvider) Retrieve(context.Context) (aws.Credentials, error) {
	return aws.Credentials{
		AccessKeyID:     "AKIDEXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		Source:          "test",
	}, nil
}

const s3TestObject = "the complete object contents fetched exactly once\n"

// fakeS3Transport answers S3 GetObject calls without DNS: signed
// (credentialed) requests can be told apart from anonymous ones.
type fakeS3Transport struct {
	t    *testing.T
	mode int
}

const (
	s3FallbackWins = iota
	s3AllAttemptsFail
	s3AllAttemptsSucceed
)

func (rt *fakeS3Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	signed := req.Header.Get("Authorization") != "" ||
		req.URL.Query().Get("X-Amz-Signature") != ""

	serveFull := rt.mode == s3AllAttemptsSucceed ||
		(rt.mode == s3FallbackWins && !signed)

	hdr := http.Header{}
	hdr.Set("ETag", `"etag"`)
	hdr.Set("Content-Length", strconv.Itoa(len(s3TestObject)))
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        hdr,
		ContentLength: int64(len(s3TestObject)),
		Request:       req,
	}
	if serveFull {
		resp.Body = io.NopCloser(strings.NewReader(s3TestObject))
	} else {
		// Die after seven bytes with an error whose text triggers the
		// anonymous fallback, just like a missing EC2 IMDS role would.
		resp.Body = &failingBody{
			data: []byte(s3TestObject[:7]),
			err:  errSimulatedIMDSRole,
		}
	}
	return resp, nil
}

func newS3TestFetcher(t *testing.T, mode int) Fetcher {
	t.Helper()
	f := newCandidateFetcher(t)
	reqNoError(t, f.newHttpClient())
	f.client.client = &http.Client{Transport: &fakeS3Transport{t: t, mode: mode}}
	f.AWSConfig = &aws.Config{
		Region:      "us-east-1",
		Credentials: testCredentialsProvider{},
	}
	return f
}

func s3AccessPointURL(t *testing.T) url.URL {
	t.Helper()
	u, err := url.Parse("arn:aws:s3:us-east-1:123456789012:accesspoint/test/object/key")
	reqNoError(t, err)
	return *u
}

// TestFetchFromS3Candidates covers the S3 authenticated -> anonymous fallback
// with isolated per-attempt candidates, both in memory and on disk, including
// the distinct outcomes for a successful fallback, total failure, and a
// complete-but-undigest-verified object.
func TestFetchFromS3Candidates(t *testing.T) {
	objectSum := sha512.Sum512([]byte(s3TestObject))
	u := s3AccessPointURL(t)

	t.Run("partial credentialed download then anonymous success to buffer", func(t *testing.T) {
		f := newS3TestFetcher(t, s3FallbackWins)
		data, err := f.FetchToBuffer(u, FetchOptions{
			Hash:        sha512.New(),
			ExpectedSum: objectSum[:],
		})
		reqNoError(t, err)
		reqEqual(t, s3TestObject, string(data),
			"the authenticated prefix must not be spliced onto the anonymous object")
	})

	t.Run("partial credentialed download then anonymous success to file", func(t *testing.T) {
		before := candidateTempFiles(t)
		f := newS3TestFetcher(t, s3FallbackWins)
		dest, err := os.CreateTemp("", "ignition-test-dest-*")
		reqNoError(t, err)
		defer func() { _ = os.Remove(dest.Name()) }()
		defer func() { _ = dest.Close() }()

		reqNoError(t, f.Fetch(u, dest, FetchOptions{
			Hash:        sha512.New(),
			ExpectedSum: objectSum[:],
		}))
		got, err := os.ReadFile(dest.Name())
		reqNoError(t, err)
		reqEqual(t, s3TestObject, string(got))

		reqElementsMatch(t, before, candidateTempFiles(t),
			"temporary candidate files leaked")
	})

	t.Run("both attempts fail keeps the distinct combined error", func(t *testing.T) {
		f := newS3TestFetcher(t, s3AllAttemptsFail)
		data, err := f.FetchToBuffer(u, FetchOptions{})
		reqError(t, err)
		reqNil(t, data)
		assert.Contains(t, err.Error(), "anonymously")
		assert.Contains(t, err.Error(), "authenticated fetch also failed")
	})

	t.Run("complete object failing digest returns mismatch and no bytes", func(t *testing.T) {
		f := newS3TestFetcher(t, s3AllAttemptsSucceed)
		badSum := make([]byte, sha512.Size)
		badSum[0] = 0xff
		data, err := f.FetchToBuffer(u, FetchOptions{
			Hash:        sha512.New(),
			ExpectedSum: badSum,
		})
		reqError(t, err)
		reqNil(t, data)
		var mismatch util.ErrHashMismatch
		reqErrorAs(t, err, &mismatch)
	})
}
