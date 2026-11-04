package api

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
)

const (
	postFormOverheadLimit int64 = 20 * 1024
	postScalarCountLimit        = 128
	postLookaheadLimit    int64 = 32 * 1024
	postBeforeFileLimit   int64 = postFormOverheadLimit + postLookaheadLimit
	postDefaultFileLimit  int64 = 5 << 30
)

type postUpload struct {
	bucket, key, filename string
	fields                map[string]string
	reader                *multipart.Reader
	wire                  *postWireReader
	policy                postPolicy
	minimumFileSize       int64
	maximumFileSize       int64
	options               s3.ObjectPutOptions
	checksum              postChecksum
	deadline              time.Time
	successStatus         int
	redirect              *url.URL
	body                  verifiedAWSBody
	// file preserves the MIME part identity; production byte consumption must
	// use fileRead so cumulative limits have exactly one accounting owner.
	file                   *multipart.Part
	fileRead               io.Reader
	fileCounter            *postFileReader
	limitSnapshot          SpoolLimits
	authenticatedAccessKey string
	requestBody            io.Closer
	scalarBytes            int64
	expectedWireLength     int64
	closeOnce              sync.Once
	fileSeen               bool
}

func (u *postUpload) Close() error {
	if u == nil {
		return nil
	}
	var closeErr error
	u.closeOnce.Do(func() {
		if u.body != nil {
			closeErr = u.body.Close()
			u.body = nil
		}
		// Do not close the request body or multipart.Part here: either may drain
		// unread file bytes before authorization. The HTTP server owns request-body
		// cleanup; Finish closes it only after consuming the complete form.
		if u.options.SSE != nil && u.options.SSE.Customer != nil {
			u.options.SSE.Customer.Close()
		}
		u.file = nil
		u.fileCounter = nil
		u.fileRead = nil
		u.reader = nil
		u.wire = nil
		u.fields = nil
		u.policy = postPolicy{}
		u.filename, u.key, u.bucket = "", "", ""
	})
	return closeErr
}

func (u *postUpload) bindDestination(bucket string) error {
	if u == nil || bucket == "" {
		return ErrPostPolicyDenied
	}
	if err := (crypto.ObjectContext{Bucket: bucket, Key: u.key}).Validate(); err != nil {
		return ErrPostPolicyDenied
	}
	if submitted, present := postFormField(u.fields, "bucket", ""); present && submitted != bucket {
		return ErrPostPolicyDenied
	}
	u.bucket = bucket
	return nil
}

func (u *postUpload) Finish() error {
	if u == nil || u.reader == nil || u.wire == nil || u.fileCounter == nil {
		return ErrPostFormMalformed
	}
	if !u.fileCounter.eof {
		return ErrPostIncompleteBody
	}
	if u.wire.fileBytes > u.wire.fileLimit {
		return ErrPostEntityTooLarge
	}
	if _, err := u.reader.NextRawPart(); err != io.EOF {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return ErrPostIncompleteBody
		}
		if errors.Is(err, ErrPostEntityTooLarge) || u.wire.tooLarge {
			return ErrPostEntityTooLarge
		}
		return ErrPostFormMalformed
	}
	if !u.wire.closed && !u.wire.closePending {
		return ErrPostIncompleteBody
	}
	if err := u.wire.Finish(); err != nil {
		return err
	}
	if u.expectedWireLength >= 0 && u.wire.read != u.expectedWireLength {
		return ErrPostIncompleteBody
	}
	if u.requestBody != nil {
		if err := u.requestBody.Close(); err != nil {
			return ErrPostIncompleteBody
		}
		u.requestBody = nil
	}
	return nil
}

// postFileReader is the single owner of decoded file-byte accounting. Its
// caller (the post spooler in the later phase) must consume it to EOF before
// Finish validates framing; Finish never drains or recounts file contents.
type postFileReader struct {
	part   *multipart.Part
	wire   *postWireReader
	eof    bool
	onRead func(int64)
}

func (r *postFileReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r == nil || r.part == nil || r.wire == nil {
		return 0, ErrPostIncompleteBody
	}
	n, err := r.part.Read(p)
	if n > 0 {
		if addErr := r.wire.addFileBytes(int64(n)); addErr != nil {
			return n, addErr
		}
		if r.onRead != nil {
			r.onRead(int64(n))
		}
	}
	if err == io.EOF {
		r.eof = true
		return n, io.EOF
	}
	if err != nil {
		if errors.Is(err, ErrPostEntityTooLarge) || r.wire.tooLarge {
			return n, ErrPostEntityTooLarge
		}
		if errors.Is(err, ErrStreamingCanceled) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return n, ErrStreamingCanceled
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return n, ErrPostIncompleteBody
		}
		return n, ErrPostIncompleteBody
	}
	if n == 0 && err == nil {
		return 0, ErrPostIncompleteBody
	}
	return n, err
}

func postUploadFromContext(r *http.Request) (*postUpload, bool) {
	if r == nil {
		return nil, false
	}
	u, ok := r.Context().Value(postUploadContextKey{}).(*postUpload)
	return u, ok && u != nil
}

type postUploadContextKey struct{}

func isPostObjectRequest(r *http.Request) bool {
	if r == nil || r.Method != http.MethodPost || r.URL == nil || r.URL.RawQuery != "" || r.URL.ForceQuery {
		return false
	}
	path := r.URL.Path
	if path == "" || !strings.HasPrefix(path, "/") {
		return false
	}
	trimmed := strings.TrimSuffix(path, "/")
	if trimmed == "" || strings.HasSuffix(trimmed, "/") || strings.Count(trimmed, "/") != 1 || strings.Contains(trimmed, "//") || strings.ContainsAny(trimmed, "?#") {
		return false
	}
	contentType, ok := postContentType(r.Header)
	if !ok {
		return false
	}
	if strings.ContainsAny(contentType, "\r\n\x00") {
		return false
	}
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.EqualFold(mediaType, "multipart/form-data") {
		return false
	}
	boundary := params["boundary"]
	if boundary == "" || len(boundary) > 70 {
		return false
	}
	var boundaryValidator multipart.Writer
	return boundaryValidator.SetBoundary(boundary) == nil
}

func postContentType(header http.Header) (string, bool) {
	var value string
	count := 0
	for name, values := range header {
		if !strings.EqualFold(name, "Content-Type") {
			continue
		}
		for _, candidate := range values {
			count++
			value = candidate
		}
	}
	return value, count == 1
}

// postWireReader tracks bytes beneath multipart's bufio.Reader, enforces a
// dynamic wire limit, and observes the raw delimiter framing independently of
// MIME parsing. Its scan window is bounded to boundary+8 bytes.
type postWireReader struct {
	r               io.Reader
	read, limit     int64
	fileLimit       int64
	fileBytes       int64
	boundary        string
	scan            []byte
	pendingCR       bool
	closePending    bool
	closeCR         bool
	closeBareLF     bool
	closePadding    bool
	lineLength      int64
	lineWhitespace  bool
	linePrefix      bool
	preambleBytes   int64
	opened, closed  bool
	invalidEpilogue bool
	fileRecognized  bool
	tooLarge        bool
}

func newPostWireReader(r io.Reader, boundary string, fileLimit int64) *postWireReader {
	if fileLimit < 0 {
		fileLimit = 0
	}
	window := make([]byte, 0, len(boundary)+8)
	return &postWireReader{r: r, limit: postBeforeFileLimit, fileLimit: fileLimit, boundary: boundary, scan: window, lineWhitespace: true, linePrefix: true}
}

func (r *postWireReader) recognizeFile() error {
	if r == nil || r.fileRecognized {
		return nil
	}
	r.fileRecognized = true
	if r.fileLimit > int64(^uint64(0)>>1)-postFormOverheadLimit {
		r.tooLarge = true
		return ErrPostEntityTooLarge
	}
	r.limit = r.fileLimit + postFormOverheadLimit
	return nil
}

func (r *postWireReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r == nil || r.r == nil {
		return 0, ErrPostIncompleteBody
	}
	if r.tooLarge {
		return 0, ErrPostEntityTooLarge
	}
	remaining := r.limit - r.read
	if remaining < 0 {
		return 0, ErrPostEntityTooLarge
	}
	capRead := remaining + 1
	if int64(len(p)) > capRead {
		p = p[:capRead]
	}
	n, err := r.r.Read(p)
	if n > 0 {
		r.read += int64(n)
		r.observe(p[:n])
		if r.read > r.limit {
			r.tooLarge = true
			return n, ErrPostEntityTooLarge
		}
	}
	if r.tooLarge {
		return n, ErrPostEntityTooLarge
	}
	if n == 0 && err == nil {
		return 0, ErrPostIncompleteBody
	}
	if err != nil && err != io.EOF {
		if errors.Is(err, ErrPostEntityTooLarge) {
			return n, ErrPostEntityTooLarge
		}
		if errors.Is(err, ErrStreamingCanceled) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return n, ErrStreamingCanceled
		}
		return n, ErrPostIncompleteBody
	}
	return n, err
}

func (r *postWireReader) addFileBytes(n int64) error {
	if r == nil || n < 0 || !r.fileRecognized || r.fileBytes > r.fileLimit || n > r.fileLimit-r.fileBytes {
		return ErrPostEntityTooLarge
	}
	r.fileBytes += n
	return nil
}

func (r *postWireReader) observe(data []byte) {
	if r == nil {
		return
	}
	maxKeep := len(r.boundary) + 8
	for _, b := range data {
		if r.closed {
			if b != ' ' && b != '\t' && b != '\r' && b != '\n' {
				r.invalidEpilogue = true
			}
			continue
		}
		if !r.opened {
			r.observePreambleByte(b, maxKeep)
			if r.tooLarge {
				return
			}
			continue
		}
		if r.closePending {
			if !r.closeCR && (b == ' ' || b == '\t') {
				r.closePadding = true
				continue
			}
			if !r.closeCR && b == '\r' {
				r.closeCR = true
				continue
			}
			if !r.closeCR && b == '\n' {
				r.invalidEpilogue = true
				r.closePending = false
				continue
			}
			if r.closeCR && b == '\n' {
				if r.closeBareLF {
					r.invalidEpilogue = true
				} else {
					r.closed = true
				}
				r.closePending, r.closeCR, r.closeBareLF, r.closePadding = false, false, false, false
				continue
			}
			// This closing-looking sequence did not complete a delimiter line;
			// keep treating its bytes as file data.
			r.closePending, r.closeCR, r.closeBareLF, r.closePadding = false, false, false, false
			if len(r.scan) > 0 {
				copy(r.scan, r.scan[1:])
				r.scan = r.scan[:len(r.scan)-1]
			}
		}
		r.appendScanByte(b, maxKeep)
		bareLine := "\n--" + r.boundary + "\r\n"
		if strings.HasSuffix(string(r.scan), bareLine) {
			start := len(r.scan) - len(bareLine)
			if start == 0 || r.scan[start-1] != '\r' {
				r.invalidEpilogue = true
				continue
			}
		}
		closing := "\r\n--" + r.boundary + "--"
		bareClosing := "\n--" + r.boundary + "--"
		if strings.HasSuffix(string(r.scan), closing) {
			r.closePending = true
		} else if strings.HasSuffix(string(r.scan), bareClosing) {
			r.closePending, r.closeBareLF = true, true
		}
	}
}

func (r *postWireReader) observePreambleByte(b byte, maxKeep int) {
	if r.pendingCR {
		r.pendingCR = false
		if b == '\n' {
			if r.lineLength == int64(len(r.boundary)+2) && string(r.scan) == "--"+r.boundary {
				r.opened = true
			} else if !r.lineWhitespace {
				r.invalidEpilogue = true
			} else {
				r.preambleBytes += r.lineLength + 2
				if r.preambleBytes > postFormOverheadLimit {
					r.tooLarge = true
				}
			}
			r.scan = r.scan[:0]
			r.lineLength, r.lineWhitespace, r.linePrefix = 0, true, true
			return
		}
		r.invalidEpilogue = true
		return
	}
	if b == '\r' {
		r.pendingCR = true
		return
	}
	if b == '\n' {
		r.invalidEpilogue = true
		return
	}
	r.lineLength++
	if b != ' ' && b != '\t' {
		r.lineWhitespace = false
	}
	if r.lineLength <= int64(len(r.boundary)+2) {
		maxPrefix := len(r.boundary) + 2
		if len(r.scan) < maxPrefix {
			r.scan = append(r.scan, b)
		}
	} else {
		r.linePrefix = false
	}
	if r.lineLength <= int64(len(r.boundary)+2) && !strings.HasPrefix("--"+r.boundary, string(r.scan)) {
		r.linePrefix = false
	}
}

func (r *postWireReader) appendScanByte(b byte, maxKeep int) {
	if len(r.scan) >= maxKeep {
		copy(r.scan, r.scan[1:])
		r.scan = r.scan[:maxKeep-1]
	}
	r.scan = append(r.scan, b)
}

func (r *postWireReader) Finish() error {
	if r == nil || r.r == nil {
		return ErrPostIncompleteBody
	}
	buffer := make([]byte, 32*1024)
	for {
		n, err := r.Read(buffer)
		if err == io.EOF {
			// Read may return final bytes and EOF together; those bytes have
			// already been observed and counted by Read.
			break
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrPostIncompleteBody
		}
	}
	if r.invalidEpilogue {
		return ErrPostFormMalformed
	}
	if r.tooLarge {
		return ErrPostEntityTooLarge
	}
	if !r.opened {
		return ErrPostFormMalformed
	}
	if !r.closed && !r.closePending {
		return ErrPostIncompleteBody
	}
	if r.closePending {
		if r.closeCR || r.closeBareLF {
			return ErrPostFormMalformed
		}
		// A closing delimiter with optional horizontal padding may terminate
		// at exact HTTP EOF, as permitted by MIME's closing-line grammar.
		r.closed = true
		r.closePending = false
	}
	if !r.closed {
		return ErrPostIncompleteBody
	}
	if r.pendingCR {
		return ErrPostFormMalformed
	}
	if !r.closed || r.invalidEpilogue {
		return ErrPostFormMalformed
	}
	if r.fileBytes < 0 || r.read-r.fileBytes > postFormOverheadLimit {
		return ErrPostEntityTooLarge
	}
	return nil
}

func parsePostUpload(r *http.Request, globalLimit int64) (*postUpload, error) {
	if !isPostObjectRequest(r) {
		return nil, ErrPostFormMalformed
	}
	if r.URL.Path == "/" || strings.Contains(strings.Trim(r.URL.Path, "/"), "/") {
		return nil, ErrPostFormMalformed
	}
	if r.Body == nil {
		return nil, ErrPostIncompleteBody
	}
	contentType, ok := postContentType(r.Header)
	if !ok {
		return nil, ErrPostFormMalformed
	}
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.EqualFold(mediaType, "multipart/form-data") {
		return nil, ErrPostFormMalformed
	}
	boundary := params["boundary"]
	if globalLimit <= 0 || globalLimit > postDefaultFileLimit {
		globalLimit = postDefaultFileLimit
	}
	wire := newPostWireReader(r.Body, boundary, globalLimit)
	reader := multipart.NewReader(wire, boundary)
	upload := &postUpload{fields: make(map[string]string), reader: reader, wire: wire, maximumFileSize: math.MaxInt64, expectedWireLength: r.ContentLength, requestBody: r.Body}
	seen := make(map[string]struct{})
	for scalarCount := 0; scalarCount <= postScalarCountLimit; scalarCount++ {
		part, partErr := reader.NextRawPart()
		if partErr == io.EOF {
			if wire.closed || wire.closePending {
				if !upload.fileSeen {
					_ = upload.Close()
					return nil, ErrPostFormMalformed
				}
				if err := wire.Finish(); err != nil {
					_ = upload.Close()
					return nil, err
				}
				if upload.expectedWireLength >= 0 && wire.read != upload.expectedWireLength {
					_ = upload.Close()
					return nil, ErrPostIncompleteBody
				}
				return upload, nil
			}
			_ = upload.Close()
			return nil, ErrPostFormMalformed
		}
		if partErr != nil {
			if errors.Is(partErr, ErrPostEntityTooLarge) {
				_ = upload.Close()
				return nil, ErrPostEntityTooLarge
			}
			if errors.Is(partErr, io.ErrUnexpectedEOF) {
				_ = upload.Close()
				return nil, ErrPostIncompleteBody
			}
			if wire.tooLarge {
				_ = upload.Close()
				return nil, ErrPostEntityTooLarge
			}
			_ = upload.Close()
			return nil, ErrPostFormMalformed
		}
		if hasDuplicateCriticalMIMEHeader(part.Header) || len(part.Header.Values("Content-Disposition")) != 1 || len(part.Header.Values("Content-Type")) > 1 || len(part.Header.Values("Content-Transfer-Encoding")) != 0 {
			_ = upload.Close()
			return nil, ErrPostFormMalformed
		}
		media, _, mediaErr := mime.ParseMediaType(part.Header.Get("Content-Type"))
		if mediaErr != nil && part.Header.Get("Content-Type") != "" || mediaErr == nil && strings.HasPrefix(strings.ToLower(media), "multipart/") {
			_ = upload.Close()
			return nil, ErrPostFormMalformed
		}
		disposition, dispositionParams, dispErr := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
		if dispErr != nil || !strings.EqualFold(disposition, "form-data") {
			_ = upload.Close()
			return nil, ErrPostFormMalformed
		}
		name, exists := dispositionParams["name"]
		if !exists || name == "" || strings.ContainsAny(name, "\x00\r\n") {
			_ = upload.Close()
			return nil, ErrPostFormMalformed
		}
		canonical := asciiPostFold(name)
		if !utf8.ValidString(name) {
			_ = upload.Close()
			return nil, ErrPostFormMalformed
		}
		if _, duplicate := seen[canonical]; duplicate {
			_ = upload.Close()
			return nil, ErrPostFormMalformed
		}
		seen[canonical] = struct{}{}
		filename, hasFilename := dispositionParams["filename"]
		if canonical == "file" {
			if upload.fileSeen {
				_ = upload.Close()
				return nil, ErrPostFormMalformed
			}
			if err := wire.recognizeFile(); err != nil {
				_ = upload.Close()
				return nil, err
			}
			if wire.read > postBeforeFileLimit {
				_ = upload.Close()
				return nil, ErrPostEntityTooLarge
			}
			if part.Header.Get("Content-Disposition") == "" {
				_ = upload.Close()
				return nil, ErrPostFormMalformed
			}
			upload.fileCounter = &postFileReader{part: part, wire: wire}
			upload.file = part
			upload.fileRead = upload.fileCounter
			upload.filename = filename
			if hasFilename {
				if !utf8.ValidString(filename) || strings.ContainsAny(filename, "\x00\r\n") {
					_ = upload.Close()
					return nil, ErrPostFormMalformed
				}
			} else {
				filename = ""
			}
			fields, basename, expandErr := expandPostFilename(upload.fields, filename)
			if expandErr != nil {
				_ = upload.Close()
				return nil, expandErr
			}
			upload.fields = fields
			upload.filename = basename
			upload.key = fields["key"]
			upload.fileSeen = true
			if upload.key == "" {
				_ = upload.Close()
				return nil, ErrMissingCredentials
			}
			if len(upload.key) > 1024 || !utf8.ValidString(upload.key) || strings.ContainsAny(upload.key, "\x00\r\n") {
				_ = upload.Close()
				return nil, ErrPostPolicyDenied
			}
			// The destination binding is attached from the route by the later auth
			// phase. The parser retains literal field bytes only.
			return upload, nil
		}
		if hasFilename {
			_ = upload.Close()
			return nil, ErrPostFormMalformed
		}
		if !utf8.ValidString(name) {
			_ = upload.Close()
			return nil, ErrPostFormMalformed
		}
		if scalarCount == postScalarCountLimit {
			_ = upload.Close()
			return nil, ErrPostEntityTooLarge
		}
		canonicalName, ok := canonicalPostField(name)
		if !ok {
			_ = upload.Close()
			return nil, ErrPostUnsupported
		}
		if canonicalName == "content-length-range" || canonicalName == "file" {
			if canonicalName == "content-length-range" {
				_ = upload.Close()
				return nil, ErrPostUnsupported
			}
		}
		if strings.HasPrefix(canonicalName, "x-ignore-") {
			// Deliberately discard ignore values; they cannot affect policy or options.
			remaining := postFormOverheadLimit - upload.scalarBytes
			if remaining < 0 {
				_ = upload.Close()
				return nil, ErrPostEntityTooLarge
			}
			value, readErr := io.ReadAll(io.LimitReader(part, remaining+1))
			if readErr != nil || int64(len(value)) > remaining {
				_ = upload.Close()
				if int64(len(value)) > remaining {
					return nil, ErrPostEntityTooLarge
				}
				return nil, ErrPostIncompleteBody
			}
			if !utf8.Valid(value) || bytes.IndexByte(value, 0) >= 0 || bytes.ContainsAny(value, "\r\n") {
				_ = upload.Close()
				return nil, ErrPostFormMalformed
			}
			upload.scalarBytes += int64(len(value))
			continue
		}
		remaining := postFormOverheadLimit - upload.scalarBytes
		if remaining < 0 {
			_ = upload.Close()
			return nil, ErrPostEntityTooLarge
		}
		value, readErr := io.ReadAll(io.LimitReader(part, remaining+1))
		if readErr != nil || int64(len(value)) > remaining {
			_ = upload.Close()
			if int64(len(value)) > remaining {
				return nil, ErrPostEntityTooLarge
			}
			return nil, ErrPostIncompleteBody
		}
		upload.scalarBytes += int64(len(value))
		if !utf8.Valid(value) || bytes.IndexByte(value, 0) >= 0 || bytes.ContainsAny(value, "\r\n") {
			_ = upload.Close()
			return nil, ErrPostFormMalformed
		}
		upload.fields[canonicalName] = string(value)
	}
	_ = upload.Close()
	return nil, ErrPostEntityTooLarge
}

func hasDuplicateCriticalMIMEHeader(header textproto.MIMEHeader) bool {
	for name, values := range header {
		folded := asciiPostFold(name)
		switch folded {
		case "content-disposition", "content-type", "content-transfer-encoding":
			if len(values) > 1 {
				return true
			}
		}
	}
	return false
}
