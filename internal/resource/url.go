// Copyright 2016 CoreOS, Inc.
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
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"cloud.google.com/go/compute/metadata"
	configErrors "github.com/coreos/ignition/v2/config/shared/errors"
	"github.com/coreos/ignition/v2/internal/log"
	"github.com/coreos/ignition/v2/internal/util"
	"github.com/coreos/vcontext/report"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/coreos/ignition/v2/config/v3_7_experimental/types"
	providersUtil "github.com/coreos/ignition/v2/internal/providers/util"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/pin/tftp"
	"github.com/vincent-petithory/dataurl"
)

const (
	IPv4 = "ipv4"
	IPv6 = "ipv6"
)

var (
	ErrSchemeUnsupported      = errors.New("unsupported source scheme")
	ErrPathNotAbsolute        = errors.New("path is not absolute")
	ErrNotFound               = errors.New("resource not found")
	ErrFailed                 = errors.New("failed to fetch resource")
	ErrCompressionUnsupported = errors.New("compression is not supported with that scheme")
	ErrNeedNet                = errors.New("resource requires networking")

	// ConfigHeaders are the HTTP headers that should be used when the Ignition
	// config is being fetched
	configHeaders = http.Header{
		"Accept-Encoding": []string{"identity"},
		"Accept":          []string{"application/vnd.coreos.ignition+json;version=3.6.0, */*;q=0.1"},
	}

	// We could derive this info from aws-sdk-go/aws/endpoints/defaults.go,
	// but hardcoding it allows us to unit-test that specific regions
	// are used for hinting
	awsPartitionRegionHints = map[string]string{
		"aws":        "us-east-1",
		"aws-cn":     "cn-north-1",
		"aws-us-gov": "us-gov-west-1",
	}
)

// Fetcher holds settings for fetching resources from URLs
type Fetcher struct {
	// The logger object to use when logging information.
	Logger *log.Logger

	// client is the http client that will be used when fetching http(s)
	// resources. If left nil, one will be created and used, but this means any
	// timeouts Ignition was configured to used will be ignored.
	client *HttpClient

	// AWSConfig is the AWS SDK v2 config to use for S3 interactions.
	AWSConfig *aws.Config

	// The region where the AWS machine trying to fetch is.
	// This is used as a hint to fetch the S3 bucket from the right partition and region.
	S3RegionHint string

	// GCSTokenSource provides OAuth2 tokens for Google Cloud Storage
	// access. It is initialized lazily on first GCS fetch when running
	// on GCE with an associated service account.
	GCSTokenSource oauth2.TokenSource

	// Azure credential to use when fetching resources from Azure Blob Storage.
	// using DefaultAzureCredential()
	AzSession *azidentity.DefaultAzureCredential

	// Whether to only attempt fetches which can be performed offline. This
	// currently only includes the "data" scheme. Other schemes will result in
	// ErrNeedNet. In the future, we can improve on this by dropping this
	// and just making sure that we canonicalize all "insufficient
	// network"-related errors to ErrNeedNet. That way, distro integrators
	// could distinguish between "partial" and full network bring-up.
	Offline bool
}

type FetchOptions struct {
	// Headers are the http headers that will be used when fetching http(s)
	// resources. They have no effect on other fetching schemes.
	Headers http.Header

	// Hash is the hash to use when calculating a fetched resource's hash. If
	// left as nil, no hash will be calculated.
	Hash hash.Hash

	// The expected sum to be produced by the given hasher. If the Hash field is
	// nil, this field is ignored.
	ExpectedSum []byte

	// Compression specifies the type of compression to use when decompressing
	// the fetched object. If left empty, no decompression will be used.
	Compression string

	// HTTPVerb is an HTTP request method to indicate the desired action to
	// be performed for a given resource.
	HTTPVerb string

	// LocalPort is a function returning a local port used to establish the TCP connection.
	// Most of the time, letting the Kernel choose a random port is enough.
	LocalPort func() int

	// List of HTTP codes to retry that usually would be considered as complete.
	// Status codes >= 500 are always retried.
	RetryCodes []int
}

// FetchToBuffer will fetch the given url into memory. It will return the
// downloaded contents, or an error if one was encountered. When the fetch
// involves authenticated and unauthenticated attempts (Azure Blob or S3),
// every attempt writes into a private candidate buffer; only the contents of
// an attempt which was fully read, decompressed and digest-verified are
// returned, and no partial contents are ever returned on error.
func (f *Fetcher) FetchToBuffer(u url.URL, opts FetchOptions) ([]byte, error) {
	if f.Offline && util.UrlNeedsNet(u) {
		return nil, ErrNeedNet
	}

	var err error
	dest := new(bytes.Buffer)
	switch u.Scheme {
	case "http", "https":
		return f.fetchHTTPWithAzureFallbackToBuffer(u, opts)
	case "tftp":
		err = f.fetchFromTFTP(u, dest, opts)
	case "data":
		err = f.fetchFromDataURL(u, dest, opts)
	case "s3", "arn":
		return f.fetchFromS3ToBuffer(u, opts)
	case "gs":
		err = f.fetchFromGCS(u, dest, opts)
	case "":
		return nil, nil
	default:
		return nil, ErrSchemeUnsupported
	}
	if err != nil {
		return nil, err
	}
	return dest.Bytes(), nil
}

// s3buf is a wrapper around the aws.WriteAtBuffer that also allows reading and seeking.
// Read() and Seek() are only safe to call after the download call is made. This is only for
// use with fetchFromS3* functions.
type s3buf struct {
	*manager.WriteAtBuffer
	// only safe to call read/seek after finishing writing. Not safe for parallel use
	reader io.ReadSeeker
}

func (s *s3buf) Read(p []byte) (int, error) {
	if s.reader == nil {
		s.reader = bytes.NewReader(s.Bytes())
	}
	return s.reader.Read(p)
}

func (s *s3buf) Seek(offset int64, whence int) (int64, error) {
	if s.reader == nil {
		s.reader = bytes.NewReader(s.Bytes())
	}
	return s.reader.Seek(offset, whence)
}

// Fetch calls the appropriate FetchFrom* function based on the scheme of the
// given URL. The results will be decompressed if compression is set in opts,
// and written into dest. If opts.Hash is set the data stream will also be
// hashed and compared against opts.ExpectedSum, and any match failures will
// result in an error being returned.
//
// Fetch expects dest to be an empty file and for the cursor in the file to be
// at the beginning. Since some url schemes (ex: s3) use chunked downloads and
// fetch chunks out of order, Fetch's behavior when dest is not an empty file is
// undefined.
//
// Schemes which try more than one authentication or protocol (Azure Blob
// with an HTTP(S) fallback, and S3 with an anonymous fallback) never write a
// failed attempt's bytes, file offset, or hash state into dest. Each attempt
// streams into its own private temporary candidate, and only the candidate
// which is fully read, decompressed and digest-verified is copied into dest;
// every other candidate is discarded. On such an error dest is left empty,
// and callers which fetch into their own temporary file (see exec/util) only
// rename it into place after success, so partial contents can neither be
// observed nor published.
func (f *Fetcher) Fetch(u url.URL, dest *os.File, opts FetchOptions) error {
	if f.Offline && util.UrlNeedsNet(u) {
		return ErrNeedNet
	}
	switch u.Scheme {
	case "http", "https":
		return f.fetchHTTPWithAzureFallbackToFile(u, dest, opts)
	case "tftp":
		return f.fetchFromTFTP(u, dest, opts)
	case "data":
		return f.fetchFromDataURL(u, dest, opts)
	case "s3", "arn":
		return f.fetchFromS3ToFile(u, dest, opts)
	case "gs":
		return f.fetchFromGCS(u, dest, opts)
	case "":
		return nil
	default:
		return ErrSchemeUnsupported
	}
}

// fetchCandidateFunc performs one authentication or protocol attempt,
// writing the attempt's stream into cand. It must return nil only after the
// whole stream has been read, decompressed and digest-verified; any bytes
// written after a returned error belong exclusively to this attempt and must
// never reach another attempt or the caller.
type fetchCandidateFunc func(cand io.Writer) error

// fetchToBufferWithFallback runs the given attempts in order, each against a
// fresh in-memory candidate. The first attempt which completes successfully
// wins and its exact contents are returned; failed candidates are dropped so
// their bytes and hash state cannot be continued by a later attempt. If every
// attempt fails, the last error is returned along with no contents.
func (f *Fetcher) fetchToBufferWithFallback(attempts []fetchCandidateFunc) ([]byte, error) {
	var err error
	for _, attempt := range attempts {
		cand := new(bytes.Buffer)
		if err = attempt(cand); err == nil {
			return cand.Bytes(), nil
		}
	}
	return nil, err
}

// fetchToFileWithFallback runs the given attempts in order, each against a
// fresh private temporary file candidate. The first attempt which completes
// successfully wins and only its verified contents are copied into dest; all
// candidate files are removed. If every attempt fails, the last error is
// returned and dest is left untouched (and empty). A publication error is
// final: the winner was already fully verified, so no other protocol is tried.
func (f *Fetcher) fetchToFileWithFallback(dest *os.File, attempts []fetchCandidateFunc) error {
	var err error
	dir := filepath.Dir(dest.Name())
	for _, attempt := range attempts {
		cand, candErr := newFetchCandidate(dir)
		if candErr != nil {
			return candErr
		}
		if err = attempt(cand); err == nil {
			err = publishFileCandidate(dest, cand)
			releaseFetchCandidate(cand)
			return err
		}
		releaseFetchCandidate(cand)
	}
	return err
}

// fetchHTTPWithAzureFallbackToBuffer performs, in order, the authenticated
// Azure Blob attempt (when AzSession is configured and the URL points at a
// blob endpoint) and the plain HTTP(S) attempt, each in an isolated
// candidate buffer. See fetchToBufferWithFallback.
func (f *Fetcher) fetchHTTPWithAzureFallbackToBuffer(u url.URL, opts FetchOptions) ([]byte, error) {
	var attempts []fetchCandidateFunc
	if f.AzSession != nil && strings.HasSuffix(u.Host, ".blob.core.windows.net") {
		attempts = append(attempts, func(cand io.Writer) error {
			err := f.fetchFromAzureBlob(u, cand, opts)
			if err != nil {
				f.Logger.Info("could not fetch %s via Azure credentials: %v", u.String(), err)
				f.Logger.Info("falling back to HTTP fetch")
			}
			return err
		})
	}
	attempts = append(attempts, func(cand io.Writer) error {
		return f.fetchFromHTTP(u, cand, opts)
	})
	return f.fetchToBufferWithFallback(attempts)
}

// fetchHTTPWithAzureFallbackToFile is the file-backed counterpart of
// fetchHTTPWithAzureFallbackToBuffer. The verified winning candidate is
// published into dest, never the partially written candidate of a failed
// attempt.
func (f *Fetcher) fetchHTTPWithAzureFallbackToFile(u url.URL, dest *os.File, opts FetchOptions) error {
	var attempts []fetchCandidateFunc
	if f.AzSession != nil && strings.HasSuffix(u.Host, ".blob.core.windows.net") {
		attempts = append(attempts, func(cand io.Writer) error {
			err := f.fetchFromAzureBlob(u, cand, opts)
			if err != nil {
				f.Logger.Info("could not fetch %s via Azure credentials: %v", u.String(), err)
				f.Logger.Info("falling back to HTTP fetch")
			}
			return err
		})
	}
	attempts = append(attempts, func(cand io.Writer) error {
		return f.fetchFromHTTP(u, cand, opts)
	})
	return f.fetchToFileWithFallback(dest, attempts)
}

// fetchCandidatePrefix is the prefix of the private temporary files backing
// individual fetch attempts.
const fetchCandidatePrefix = "ignition-fetch-"

// newFetchCandidate creates a private temporary file in dir (which should be
// the directory of the caller's destination file, so they share a filesystem)
// which backs a single authentication or protocol attempt. It is never
// shared with another attempt, so a failed attempt's bytes, cursor and (for
// s3) out-of-order chunks cannot leak into a fallback.
func newFetchCandidate(dir string) (*os.File, error) {
	return os.CreateTemp(dir, fetchCandidatePrefix+"*")
}

// releaseFetchCandidate closes and removes a candidate temporary file.
func releaseFetchCandidate(cand *os.File) {
	name := cand.Name()
	_ = cand.Close()
	_ = os.Remove(name)
}

// publishFileCandidate copies the fully read, decompressed and
// digest-verified contents of cand into dest, which is expected to be the
// empty file handed to Fetch. cand's read offset is rewound first; dest is
// truncated to defend against any pre-existing bytes.
func publishFileCandidate(dest, cand *os.File) error {
	if _, err := cand.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := dest.Truncate(0); err != nil {
		return err
	}
	if _, err := dest.Seek(0, io.SeekStart); err != nil {
		return err
	}
	_, err := io.Copy(dest, cand)
	return err
}

// FetchFromTFTP fetches a resource from u via TFTP into dest, returning an
// error if one is encountered.
func (f *Fetcher) fetchFromTFTP(u url.URL, dest io.Writer, opts FetchOptions) error {
	if !strings.ContainsRune(u.Host, ':') {
		u.Host = u.Host + ":69"
	}
	c, err := tftp.NewClient(u.Host)
	if err != nil {
		return err
	}
	wt, err := c.Receive(u.Path, "octet")
	if err != nil {
		return err
	}
	// The TFTP library takes an io.Writer to send data in to, but to decompress
	// the stream the gzip library wraps an io.Reader, so let's create a pipe to
	// connect these two things
	pReader, pWriter := io.Pipe()
	doneChan := make(chan error, 2)

	checkForDoneChanErr := func(err error) error {
		// If an error is encountered while decompressing or copying data out of
		// the pipe, there's probably an error from writing into the pipe that
		// will better describe what went wrong. This function does a
		// non-blocking read of doneChan, overriding the returned error val if
		// there's anything in doneChan.
		select {
		case writeErr := <-doneChan:
			if writeErr != nil {
				return writeErr
			}
			return err
		default:
			return err
		}
	}

	// A goroutine is used to handle writing the fetched data into the pipe
	// while also copying it out of the pipe concurrently
	go func() {
		_, err := wt.WriteTo(pWriter)
		doneChan <- err
		err = pWriter.Close()
		doneChan <- err
	}()
	err = f.decompressCopyHashAndVerify(dest, pReader, opts)
	if err != nil {
		return checkForDoneChanErr(err)
	}
	// receive the error from wt.WriteTo()
	err = <-doneChan
	if err != nil {
		return err
	}
	// receive the error from pWriter.Close()
	err = <-doneChan
	if err != nil {
		return err
	}
	return nil
}

// FetchFromHTTP fetches a resource from u via HTTP(S) into dest, returning an
// error if one is encountered.
func (f *Fetcher) fetchFromHTTP(u url.URL, dest io.Writer, opts FetchOptions) error {
	if f.client == nil {
		if err := f.newHttpClient(); err != nil {
			return err
		}
	}

	if opts.LocalPort != nil {
		var (
			d net.Dialer
			p int
		)

		host := u.Hostname()
		addr, _ := netip.ParseAddr(host)
		network := "tcp6"
		if addr.Is4() {
			network = "tcp4"
		}

		// Assert that the port is not already used.
		for {
			p = opts.LocalPort()
			l, err := net.Listen(network, fmt.Sprintf(":%d", p))
			if err != nil && errors.Is(err, syscall.EADDRINUSE) {
				continue
			} else if err == nil {
				_ = l.Close()
				break
			}
		}
		d.LocalAddr = &net.TCPAddr{Port: p}

		f.client.transport.DialContext = d.DialContext
	}

	// We do not want to redirect HTTP headers
	f.client.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		req.Header = make(http.Header)
		return nil
	}

	// TODO use .Clone() when we have a new enough golang
	// (With Rust, we'd have immutability and wouldn't need to defensively clone)
	headers := make(http.Header)
	for k, va := range configHeaders {
		for _, v := range va {
			headers.Set(k, v)
		}
	}
	for k, va := range opts.Headers {
		for _, v := range va {
			headers.Set(k, v)
		}
	}

	requestOpts := opts
	requestOpts.Headers = headers
	dataReader, status, ctxCancel, err := f.client.httpReaderWithHeader(requestOpts, u.String())
	if ctxCancel != nil {
		// whatever context getReaderWithHeader created for the request should
		// be cancelled once we're done reading the response
		defer ctxCancel()
	}
	if err != nil {
		return err
	}
	defer func() {
		_ = dataReader.Close()
	}()

	switch status {
	case http.StatusOK, http.StatusNoContent:
		break
	case http.StatusNotFound:
		return ErrNotFound
	default:
		return ErrFailed
	}

	return f.decompressCopyHashAndVerify(dest, dataReader, opts)
}

// FetchFromDataURL writes the data stored in the dataurl u into dest, returning
// an error if one is encountered.
func (f *Fetcher) fetchFromDataURL(u url.URL, dest io.Writer, opts FetchOptions) error {
	url, err := dataurl.DecodeString(u.String())
	if err != nil {
		return err
	}

	return f.decompressCopyHashAndVerify(dest, bytes.NewBuffer(url.Data), opts)
}

// fetchFromGCS fetches an object from Google Cloud Storage using the JSON API
// directly over HTTP. On GCE instances with a service account, it authenticates
// using compute metadata credentials. Otherwise it falls back to anonymous access.
func (f *Fetcher) fetchFromGCS(u url.URL, dest io.Writer, opts FetchOptions) error {
	ctx := context.Background()
	if f.GCSTokenSource == nil {
		if metadata.OnGCE() {
			if _, err := metadata.ScopesWithContext(ctx, ""); err == nil {
				f.GCSTokenSource = google.ComputeTokenSource("", "https://www.googleapis.com/auth/devstorage.read_only")
			} else {
				f.Logger.Debug("falling back to unauthenticated GCS access: %v", err)
			}
		} else {
			f.Logger.Debug("falling back to unauthenticated GCS access: not running in GCE")
		}
	}

	bucket := u.Host
	object := strings.TrimLeft(u.Path, "/")
	decodedPath := fmt.Sprintf("/storage/v1/b/%s/o/%s", bucket, object)
	rawPath := fmt.Sprintf("/storage/v1/b/%s/o/%s", bucket, url.PathEscape(object))
	gcsURL := url.URL{
		Scheme:   "https",
		Host:     "storage.googleapis.com",
		Path:     decodedPath,
		RawPath:  rawPath,
		RawQuery: "alt=media",
	}

	if opts.Headers == nil {
		opts.Headers = make(http.Header)
	}
	if f.GCSTokenSource != nil {
		token, err := f.GCSTokenSource.Token()
		if err != nil {
			return fmt.Errorf("fetching GCS auth token: %v", err)
		}
		opts.Headers.Set("Authorization", token.Type()+" "+token.AccessToken)
	}

	return f.fetchFromHTTP(gcsURL, dest, opts)
}

type s3target interface {
	io.WriterAt
	io.ReadSeeker
}

// s3Request holds the resolved request parameters and context shared by the
// authenticated and anonymous download attempts for one S3 object.
type s3Request struct {
	ctx    context.Context
	cancel context.CancelFunc
	input  *s3.GetObjectInput
	cfg    aws.Config
	region string
	bucket string
	key    string
}

// prepareS3Request resolves the bucket, key, region and request context for
// the given s3:// or arn: URL. It performs no download and is shared by both
// download attempts.
func (f *Fetcher) prepareS3Request(u url.URL) (s3Request, error) {
	req := s3Request{
		ctx:    context.Background(),
		cancel: func() {},
	}
	if f.client != nil && f.client.timeout != 0 {
		req.ctx, req.cancel = context.WithTimeout(req.ctx, f.client.timeout)
	}

	// Determine the bucket and key based on the URL scheme
	var region, regionHint string
	var err error
	switch u.Scheme {
	case "s3":
		req.bucket = u.Host
		// s3 object keys should not start with a leading slash
		// e.g., s3://bucket/path/to/object => Key: "path/to/object"
		req.key = strings.TrimLeft(u.Path, "/")
	case "arn":
		fullURL := u.Scheme + ":" + u.Opaque
		// Parse the bucket and key from the ARN Resource.
		// Also set the region for accesspoints.
		// S3 bucket ARNs don't include the region field.
		req.bucket, req.key, region, regionHint, err = f.parseARN(fullURL)
		if err != nil {
			req.cancel()
			return req, err
		}
	default:
		req.cancel()
		return req, ErrSchemeUnsupported
	}

	if f.client == nil {
		if err := f.newHttpClient(); err != nil {
			req.cancel()
			return req, err
		}
	}

	if f.AWSConfig == nil {
		f.AWSConfig = &aws.Config{Credentials: aws.AnonymousCredentials{}}
	}
	req.cfg = *f.AWSConfig

	// Determine the partition and region this bucket is in
	if region == "" {
		// We didn't get an accesspoint ARN, so we don't know the
		// region directly. Use hints if available.
		if regionHint == "" {
			// Nope; we got an unknown ARN partition value or an
			// s3:// URL.  Maybe we're running in AWS and can
			// assume the same partition we're running in?
			regionHint = f.S3RegionHint
		}
		if regionHint == "" {
			// Nope; assume aws partition.
			regionHint = "us-east-1"
		}
		// Use the region hint to ask the correct partition for the bucket's region.
		tmpClient := s3.NewFromConfig(req.cfg, func(o *s3.Options) {
			o.Region = regionHint
			o.HTTPClient = f.client.client
		})
		r, err := manager.GetBucketRegion(req.ctx, tmpClient, req.bucket)
		if err != nil {
			req.cancel()
			var bnf manager.BucketNotFound
			if errors.As(err, &bnf) {
				return req, fmt.Errorf("could not find bucket %q: %w", req.bucket, err)
			}
			return req, fmt.Errorf("couldn't determine the region for bucket %q: %w", req.bucket, err)
		}
		region = r
	}
	req.region = region

	var versionId *string
	if v, ok := u.Query()["versionId"]; ok && len(v) > 0 {
		versionId = aws.String(v[0])
	}

	req.input = &s3.GetObjectInput{
		Bucket:    &req.bucket,
		Key:       &req.key,
		VersionId: versionId,
	}
	return req, nil
}

// newS3Client builds an S3 client for the resolved region. When anonymous is
// true, the EC2 IMDS credential chain is bypassed.
func (f *Fetcher) newS3Client(cfg aws.Config, region string, anonymous bool) *s3.Client {
	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.Region = region
		o.HTTPClient = f.client.client
		o.EndpointOptions.UseDualStackEndpoint = aws.DualStackEndpointStateEnabled
		if anonymous {
			o.Credentials = aws.AnonymousCredentials{}
		}
	})
}

// newS3CandidateBuffer creates a private in-memory target for one S3 download
// attempt. A fresh one must be used for every attempt so chunks that a
// partially completed multipart download wrote out of order cannot be spliced
// into a later attempt.
func newS3CandidateBuffer() *s3buf {
	return &s3buf{
		WriteAtBuffer: manager.NewWriteAtBuffer([]byte{}),
	}
}

// verifyS3Candidate hashes the complete downloaded candidate after its
// download finished, returning a digest mismatch error without exposing any
// of the candidate's bytes. The hash is reset first, so state left by any
// other attempt never participates.
func (f *Fetcher) verifyS3Candidate(cand s3target, opts FetchOptions) error {
	if opts.Hash == nil {
		return nil
	}
	opts.Hash.Reset()
	if _, err := cand.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if _, err := io.Copy(opts.Hash, cand); err != nil {
		return err
	}
	calculatedSum := opts.Hash.Sum(nil)
	if !bytes.Equal(calculatedSum, opts.ExpectedSum) {
		return util.ErrHashMismatch{
			Calculated: hex.EncodeToString(calculatedSum),
			Expected:   hex.EncodeToString(opts.ExpectedSum),
		}
	}
	f.Logger.Debug("file matches expected sum of: %s", hex.EncodeToString(opts.ExpectedSum))
	return nil
}

// fetchFromS3ToBuffer downloads the object described by u into memory. It
// attempts to acquire IAM credentials from the EC2 metadata service, and if
// that fails attempts the object with anonymous credentials. Each attempt
// downloads into a private candidate buffer and a failed attempt's chunks are
// discarded. Only the winning attempt's fully downloaded and digest-verified
// bytes are returned.
func (f *Fetcher) fetchFromS3ToBuffer(u url.URL, opts FetchOptions) ([]byte, error) {
	if opts.Compression != "" {
		return nil, ErrCompressionUnsupported
	}
	req, err := f.prepareS3Request(u)
	if err != nil {
		return nil, err
	}
	defer req.cancel()

	cand := newS3CandidateBuffer()
	err = f.fetchFromS3WithClient(req.ctx, cand, req.input, f.newS3Client(req.cfg, req.region, false))
	if err != nil {
		// Fallback to anonymous credentials if we failed to retrieve an EC2 IMDS role.
		// The SDK does not provide a typed error for this case.
		if !strings.Contains(err.Error(), "EC2 IMDS role") {
			return nil, fmt.Errorf("error fetching object %q from bucket %q: %s", req.key, req.bucket, err.Error())
		}
		// Drop the partial authenticated candidate, including every chunk the
		// chunked download may have written out of order, before retrying.
		cand = newS3CandidateBuffer()
		anonClient := f.newS3Client(req.cfg, req.region, true)
		if err2 := f.fetchFromS3WithClient(req.ctx, cand, req.input, anonClient); err2 != nil {
			return nil, fmt.Errorf("error fetching object %q from bucket %q anonymously: %w (authenticated fetch also failed: %w)", req.key, req.bucket, err2, err)
		}
	}
	if err := f.verifyS3Candidate(cand, opts); err != nil {
		return nil, err
	}
	return cand.Bytes(), nil
}

// fetchFromS3ToFile is the file-backed counterpart of fetchFromS3ToBuffer.
// Each attempt downloads into a private temporary file candidate; only the
// winning candidate, once fully downloaded and digest-verified, is published
// into dest. All candidate temporary files are removed.
func (f *Fetcher) fetchFromS3ToFile(u url.URL, dest *os.File, opts FetchOptions) error {
	if opts.Compression != "" {
		return ErrCompressionUnsupported
	}
	req, err := f.prepareS3Request(u)
	if err != nil {
		return err
	}
	defer req.cancel()

	cand, err := newFetchCandidate(filepath.Dir(dest.Name()))
	if err != nil {
		return err
	}
	err = f.fetchFromS3WithClient(req.ctx, cand, req.input, f.newS3Client(req.cfg, req.region, false))
	if err != nil {
		// Fallback to anonymous credentials if we failed to retrieve an EC2 IMDS role.
		// The SDK does not provide a typed error for this case.
		if !strings.Contains(err.Error(), "EC2 IMDS role") {
			releaseFetchCandidate(cand)
			return fmt.Errorf("error fetching object %q from bucket %q: %s", req.key, req.bucket, err.Error())
		}
		// Discard the partial authenticated candidate before retrying so no
		// chunk can be continued by the anonymous attempt.
		releaseFetchCandidate(cand)
		cand, err = newFetchCandidate(filepath.Dir(dest.Name()))
		if err != nil {
			return err
		}
		anonClient := f.newS3Client(req.cfg, req.region, true)
		if err2 := f.fetchFromS3WithClient(req.ctx, cand, req.input, anonClient); err2 != nil {
			releaseFetchCandidate(cand)
			return fmt.Errorf("error fetching object %q from bucket %q anonymously: %w (authenticated fetch also failed: %w)", req.key, req.bucket, err2, err)
		}
	}
	if err := f.verifyS3Candidate(cand, opts); err != nil {
		releaseFetchCandidate(cand)
		return err
	}
	err = publishFileCandidate(dest, cand)
	releaseFetchCandidate(cand)
	return err
}

func (f *Fetcher) fetchFromS3WithClient(ctx context.Context, dest s3target, input *s3.GetObjectInput, client *s3.Client) error {
	downloader := manager.NewDownloader(client)     //nolint:staticcheck // SA1019: migration to transfermanager tracked separately
	_, err := downloader.Download(ctx, dest, input) //nolint:staticcheck // SA1019: see above
	return err
}

// parse the a Azure Blob Storage URL into its components:
// storage account, container, and file
func (f *Fetcher) parseAzureStorageUrl(u url.URL) (string, string, string, error) {
	storageAccount := fmt.Sprintf("%s://%s/", u.Scheme, u.Host)
	pathSegments := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(pathSegments) != 2 {
		f.Logger.Debug("invalid URL path: %s", u.Path)
		return "", "", "", fmt.Errorf("invalid URL path, ensure url has a structure of /container/filename.ign: %s", u.Path)
	}
	container := pathSegments[0]
	file := pathSegments[1]

	return storageAccount, container, file, nil
}

func (f *Fetcher) fetchFromAzureBlob(u url.URL, dest io.Writer, opts FetchOptions) error {
	// Create a context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	storageAccount, container, file, err := f.parseAzureStorageUrl(u)
	if err != nil {
		return err
	}

	// Create Azure Blob Storage client
	storageClient, err := azblob.NewClient(storageAccount, f.AzSession, nil)
	if err != nil {
		f.Logger.Debug("failed to create azblob client: %v", err)
		return fmt.Errorf("failed to create azblob client: %w", err)
	}

	downloadStream, err := storageClient.DownloadStream(ctx, container, file, nil)
	if err != nil {
		return fmt.Errorf("failed to download blob from container '%s', file '%s': %w", container, file, err)
	}
	defer func() {
		_ = downloadStream.Body.Close()
	}()

	// Process the downloaded blob
	err = f.decompressCopyHashAndVerify(dest, downloadStream.Body, opts)
	if err != nil {
		f.Logger.Debug("Error processing downloaded blob: %v", err)
		return fmt.Errorf("failed to process downloaded blob: %w", err)
	}

	return nil
}

// uncompress will wrap the given io.Reader in a decompresser specified in the
// FetchOptions, and return an io.ReadCloser with the decompressed data stream.
func (f *Fetcher) uncompress(r io.Reader, opts FetchOptions) (io.ReadCloser, error) {
	switch opts.Compression {
	case "":
		return io.NopCloser(r), nil
	case "gzip":
		return gzip.NewReader(r)
	default:
		return nil, configErrors.ErrCompressionInvalid
	}
}

// decompressCopyHashAndVerify will decompress src if necessary, copy src into
// dest until src returns an io.EOF while also calculating a hash if one is set,
// and will return an error if there's any problems with any of this or if the
// hash doesn't match the expected hash in the opts.
func (f *Fetcher) decompressCopyHashAndVerify(dest io.Writer, src io.Reader, opts FetchOptions) error {
	var decompressor io.ReadCloser
	decompressor, err := f.uncompress(src, opts)
	if err != nil {
		return err
	}
	defer func() {
		_ = decompressor.Close()
	}()
	if opts.Hash != nil {
		opts.Hash.Reset()
		dest = io.MultiWriter(dest, opts.Hash)
	}
	if _, err = io.Copy(dest, decompressor); err != nil {
		return err
	}
	if opts.Hash != nil {
		calculatedSum := opts.Hash.Sum(nil)
		if !bytes.Equal(calculatedSum, opts.ExpectedSum) {
			return util.ErrHashMismatch{
				Calculated: hex.EncodeToString(calculatedSum),
				Expected:   hex.EncodeToString(opts.ExpectedSum),
			}
		}
		f.Logger.Debug("file matches expected sum of: %s", hex.EncodeToString(opts.ExpectedSum))
	}
	return nil
}

// parseARN is a custom wrapper around arn.Parse(); it takes arnURL, a full ARN URL,
// and returns a bucket, a key, a potentially empty region, and a
// potentially empty region hint for use in region detection; or an error if
// the ARN is invalid or not for an S3 object.
// If the given arnURL is an accesspoint ARN, the region is set.
// The region is empty for S3 bucket ARNs because they don't include the region field.
func (f *Fetcher) parseARN(arnURL string) (string, string, string, string, error) {
	if !arn.IsARN(arnURL) {
		return "", "", "", "", configErrors.ErrInvalidS3ARN
	}
	s3arn, err := arn.Parse(arnURL)
	if err != nil {
		return "", "", "", "", err
	}
	if s3arn.Service != "s3" {
		return "", "", "", "", configErrors.ErrInvalidS3ARN
	}
	// empty if unrecognized partition
	regionHint := awsPartitionRegionHints[s3arn.Partition]
	// Split the ARN bucket (or accesspoint) and key by separating on slashes.
	// See https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html#arns-paths for more info.
	urlSplit := strings.Split(arnURL, "/")

	// Determine if the ARN is for an access point or a bucket.
	if strings.HasPrefix(s3arn.Resource, "accesspoint/") {
		// urlSplit must consist of arn, name of accesspoint, "object",
		// and key
		if len(urlSplit) < 4 || urlSplit[2] != "object" {
			return "", "", "", "", configErrors.ErrInvalidS3ARN
		}

		// When using GetObjectInput with an access point,
		// you provide the access point ARN in place of the bucket name.
		// For more information about access point ARNs, see Using access points
		// https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-access-points.html
		bucket := strings.Join(urlSplit[:2], "/")
		key := strings.Join(urlSplit[3:], "/")
		return bucket, key, s3arn.Region, regionHint, nil
	}
	// urlSplit must consist of name of bucket and key
	if len(urlSplit) < 2 {
		return "", "", "", "", configErrors.ErrInvalidS3ARN
	}

	// Parse out the bucket name in order to find the region with s3manager.GetBucketRegion.
	// If specified, the key is part of the Relative ID which has the format "bucket-name/object-key" according to
	// https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-arn-format.html
	bucketUrlSplit := strings.Split(urlSplit[0], ":")
	bucket := bucketUrlSplit[len(bucketUrlSplit)-1]
	key := strings.Join(urlSplit[1:], "/")
	return bucket, key, "", regionHint, nil
}

// FetchConfigDualStack is a function that takes care of fetching Ignition configuration on systems where IPv4 only, IPv6 only or both are available.
// From a high level point of view, this function will try to fetch in parallel Ignition configuration from IPv4 and/or IPv6 - if both endpoints are available, it will
// return the first configuration successfully fetched.
func FetchConfigDualStack(f *Fetcher, userdataURLs map[string]url.URL, fetchConfig func(*Fetcher, url.URL) ([]byte, error)) (types.Config, report.Report, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		err      error
		nbErrors int
		mu       sync.Mutex
	)

	cfg := make(map[url.URL][]byte)

	success := make(chan url.URL, 1)
	errors := make(chan error, 2)

	fetch := func(ctx context.Context, ip url.URL) {
		d, e := fetchConfig(f, ip)
		if e != nil {
			f.Logger.Err("fetching configuration for %s: %v", ip.String(), e)
			mu.Lock()
			err = e
			mu.Unlock()
			errors <- e
			return
		}
		_, _, parseErr := providersUtil.ParseConfig(f.Logger, d)
		if parseErr != nil {
			f.Logger.Err("parsing configuration from %s: %v", ip.String(), parseErr)
			mu.Lock()
			err = parseErr
			mu.Unlock()
			errors <- parseErr
			return
		}

		mu.Lock()
		cfg[ip] = d
		mu.Unlock()
		select {
		case success <- ip:
		default:
		}
	}

	numGoroutines := 0
	if ipv4, ok := userdataURLs[IPv4]; ok {
		go fetch(ctx, ipv4)
		numGoroutines++
	}

	if ipv6, ok := userdataURLs[IPv6]; ok {
		go fetch(ctx, ipv6)
		numGoroutines++
	}

	for {
		select {
		case ip := <-success:
			f.Logger.Debug("got configuration from: %s", ip.String())
			mu.Lock()
			data := cfg[ip]
			mu.Unlock()
			return providersUtil.ParseConfig(f.Logger, data)
		case <-errors:
			nbErrors++
			if nbErrors >= numGoroutines {
				mu.Lock()
				lastErr := err
				mu.Unlock()
				f.Logger.Debug("all routines have failed to fetch configuration, returning last known error: %v", lastErr)
				return types.Config{}, report.Report{}, lastErr
			}
		}
	}
}
