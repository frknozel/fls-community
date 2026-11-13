// archivehash advances one SHA-256 stream over an inherited regular-file FD.
// It never opens paths, writes checkpoints, or accesses the network. Its caller
// must bind a checkpoint to the signed manifest and stable file identity, and
// must keep that checkpoint private: serialized hashes are trusted state.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	maxInput  = 16 * 1024
	chunkSize = 256 * 1024
	maxBytes  = 1024 * 1024 * 1024
	maxRate   = 64 * 1024 * 1024
)

type request struct {
	Schema             int     `json:"schema"`
	State              *string `json:"state"`
	Offset             int64   `json:"offset"`
	Rows               int64   `json:"rows"`
	LimitBytes         int64   `json:"limit_bytes"`
	MaxSeconds         int64   `json:"max_seconds"`
	RateBytesPerSecond int64   `json:"rate_bytes_per_second"`
}

type response struct {
	Schema    int     `json:"schema"`
	Offset    int64   `json:"offset"`
	Rows      int64   `json:"rows"`
	State     string  `json:"state"`
	Complete  bool    `json:"complete"`
	SHA256    *string `json:"sha256"`
	ReadBytes int64   `json:"read_bytes"`
}

type codedError string

func (e codedError) Error() string { return string(e) }

type budgetClock struct {
	now   func() time.Time
	sleep func(time.Duration)
}

// Linux stat excludes atime, which can change because we read the file.
type fingerprint struct {
	dev, ino uint64
	size     int64
	mtime    syscall.Timespec
	ctime    syscall.Timespec
}

func fileFingerprint(f *os.File) (fingerprint, error) {
	var stat syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &stat); err != nil {
		return fingerprint{}, codedError("file_stat_failed")
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFREG || stat.Size < 0 {
		return fingerprint{}, codedError("regular_file_required")
	}
	return fingerprint{uint64(stat.Dev), stat.Ino, stat.Size, stat.Mtim, stat.Ctim}, nil
}

func parseRequest(reader io.Reader) (request, error) {
	var r request
	data, err := io.ReadAll(io.LimitReader(reader, maxInput+1))
	if err != nil || len(data) > maxInput {
		return r, codedError("invalid_input")
	}
	// DisallowUnknownFields alone accepts duplicate keys. Reject those too;
	// this protocol is deliberately a single flat JSON object.
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return r, codedError("invalid_input")
	}
	fields := make(map[string]bool)
	for decoder.More() {
		token, err = decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || fields[key] {
			return r, codedError("invalid_input")
		}
		fields[key] = true
		var value json.RawMessage
		if err = decoder.Decode(&value); err != nil {
			return r, codedError("invalid_input")
		}
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return r, codedError("invalid_input")
	}
	if err = decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return r, codedError("invalid_input")
	}
	required := []string{"schema", "state", "offset", "rows", "limit_bytes", "max_seconds", "rate_bytes_per_second"}
	if len(fields) != len(required) {
		return r, codedError("invalid_input")
	}
	for _, field := range required {
		if !fields[field] {
			return r, codedError("invalid_input")
		}
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&r); err != nil || r.Schema != 1 ||
		r.Offset < 0 || r.Rows < 0 || r.Rows > r.Offset ||
		r.LimitBytes < 1 || r.LimitBytes > maxBytes ||
		r.MaxSeconds < 1 || r.MaxSeconds > 60 ||
		r.RateBytesPerSecond < 1 || r.RateBytesPerSecond > maxRate {
		return request{}, codedError("invalid_input")
	}
	// JSON null for an integer otherwise silently becomes zero.
	var raw map[string]json.RawMessage
	if json.Unmarshal(data, &raw) != nil {
		return request{}, codedError("invalid_input")
	}
	for _, field := range required {
		if field != "state" && bytes.Equal(bytes.TrimSpace(raw[field]), []byte("null")) {
			return request{}, codedError("invalid_input")
		}
	}
	if r.State == nil && (r.Offset != 0 || r.Rows != 0) {
		return request{}, codedError("invalid_state")
	}
	return r, nil
}

// The supported checkpoint encoding is Go crypto/sha256's versioned sha\x03
// format: 4 magic bytes, 8 uint32 chaining words, a 64-byte partial block, and
// an 8-byte big-endian total byte count. Reject a future incompatible format
// instead of silently trusting an offset unrelated to the resumed hash state.
// The complete state is also validated by UnmarshalBinary and canonicalized.
func stateBytesCount(state []byte) (uint64, bool) {
	if len(state) != 108 || !bytes.Equal(state[:4], []byte{'s', 'h', 'a', 3}) {
		return 0, false
	}
	return binary.BigEndian.Uint64(state[len(state)-8:]), true
}

func process(r request, f *os.File, clock budgetClock) (response, error) {
	var out response
	before, err := fileFingerprint(f)
	if err != nil {
		return out, err
	}
	if r.Offset > before.size {
		return out, codedError("invalid_offset")
	}
	hash := sha256.New()
	if r.State != nil {
		state, decodeErr := base64.StdEncoding.Strict().DecodeString(*r.State)
		count, supported := stateBytesCount(state)
		if decodeErr != nil || !supported || count != uint64(r.Offset) {
			return out, codedError("invalid_state")
		}
		if hash.(encoding.BinaryUnmarshaler).UnmarshalBinary(state) != nil {
			return out, codedError("invalid_state")
		}
		canonical, marshalErr := hash.(encoding.BinaryMarshaler).MarshalBinary()
		if marshalErr != nil || !bytes.Equal(state, canonical) {
			return out, codedError("invalid_state")
		}
	}
	if position, seekErr := f.Seek(r.Offset, io.SeekStart); seekErr != nil || position != r.Offset {
		return out, codedError("file_seek_failed")
	}
	out = response{Schema: 1, Offset: r.Offset, Rows: r.Rows}
	started := clock.now()
	deadline := started.Add(time.Duration(r.MaxSeconds) * time.Second)
	buffer := make([]byte, chunkSize)
	for out.Offset < before.size && out.ReadBytes < r.LimitBytes && clock.now().Before(deadline) {
		length := min(int64(len(buffer)), r.LimitBytes-out.ReadBytes, before.size-out.Offset)
		n, readErr := f.Read(buffer[:int(length)])
		if n > 0 {
			_, _ = hash.Write(buffer[:n])
			out.Offset += int64(n)
			out.ReadBytes += int64(n)
			out.Rows += int64(bytes.Count(buffer[:n], []byte{'\n'}))
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return response{}, codedError("file_read_failed")
		}
		current, statErr := fileFingerprint(f)
		if statErr != nil {
			return response{}, statErr
		}
		if current != before {
			return response{}, codedError("file_changed")
		}
		if n == 0 || errors.Is(readErr, io.EOF) && out.Offset < before.size {
			return response{}, codedError("unexpected_eof")
		}
		// Pace every chunk, including the final one, so many small files do
		// not each bypass the rate limit. There is at most one buffer burst.
		paceUntil := started.Add(time.Duration(out.ReadBytes * int64(time.Second) / r.RateBytesPerSecond))
		if paceUntil.After(deadline) {
			paceUntil = deadline
		}
		if wait := paceUntil.Sub(clock.now()); wait > 0 {
			clock.sleep(wait)
		}
	}
	if out.Offset == before.size {
		// Do not infer EOF solely from the initial stat: an append must not
		// turn this result into a successful complete-file verification.
		var byteAfter [1]byte
		n, eofErr := f.Read(byteAfter[:])
		if n != 0 || !errors.Is(eofErr, io.EOF) {
			return response{}, codedError("file_changed")
		}
		out.Complete = true
	}
	after, err := fileFingerprint(f)
	if err != nil {
		return response{}, err
	}
	if after != before {
		return response{}, codedError("file_changed")
	}
	state, err := hash.(encoding.BinaryMarshaler).MarshalBinary()
	count, supported := stateBytesCount(state)
	if err != nil || !supported || count != uint64(out.Offset) {
		return response{}, codedError("unsupported_state")
	}
	out.State = base64.StdEncoding.EncodeToString(state)
	if out.Complete {
		digest := hex.EncodeToString(hash.Sum(nil))
		out.SHA256 = &digest
	}
	return out, nil
}

func run(args []string, input io.Reader, output io.Writer) int {
	fail := func(err error) int {
		code := "internal_error"
		var known codedError
		if errors.As(err, &known) {
			code = string(known)
		}
		_ = json.NewEncoder(output).Encode(struct {
			Schema int    `json:"schema"`
			Error  string `json:"error"`
		}{1, code})
		return 1
	}
	if len(args) != 1 || !strings.HasPrefix(args[0], "--fd=") {
		return fail(codedError("invalid_arguments"))
	}
	fdText := strings.TrimPrefix(args[0], "--fd=")
	if fdText == "" || strings.Trim(fdText, "0123456789") != "" {
		return fail(codedError("invalid_arguments"))
	}
	fd, err := strconv.ParseUint(fdText, 10, 20)
	if err != nil || fd < 3 {
		return fail(codedError("invalid_arguments"))
	}
	r, err := parseRequest(input)
	if err != nil {
		return fail(err)
	}
	f := os.NewFile(uintptr(fd), "archive-input")
	if f == nil {
		return fail(codedError("file_stat_failed"))
	}
	defer f.Close()
	out, err := process(r, f, budgetClock{now: time.Now, sleep: time.Sleep})
	if err != nil {
		return fail(err)
	}
	if err = json.NewEncoder(output).Encode(out); err != nil {
		return 1
	}
	return 0
}

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout)) }
