package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func validRequest() request {
	return request{Schema: 1, LimitBytes: maxBytes, MaxSeconds: 60, RateBytesPerSecond: maxRate}
}

func fixture(t *testing.T, content []byte) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "raw-")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write(content); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func fakeClock(afterSleep func()) (budgetClock, *time.Time) {
	now := time.Unix(1792886400, 0)
	return budgetClock{
		now: func() time.Time { return now },
		sleep: func(d time.Duration) {
			now = now.Add(d)
			if afterSleep != nil {
				afterSleep()
			}
		},
	}, &now
}

func requireCode(t *testing.T, err error, expected string) {
	t.Helper()
	if err == nil || err.Error() != expected {
		t.Fatalf("wanted %s, got %v", expected, err)
	}
}

func TestKnownFullDigestsAndRows(t *testing.T) {
	for _, content := range [][]byte{nil, []byte("abc"), []byte("a\nb\nlast"), {0, 255, 10, 0, 13, 10, 1}} {
		t.Run(hex.EncodeToString(content), func(t *testing.T) {
			clock, _ := fakeClock(nil)
			out, err := process(validRequest(), fixture(t, content), clock)
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(content)
			if !out.Complete || out.SHA256 == nil || *out.SHA256 != hex.EncodeToString(sum[:]) ||
				out.ReadBytes != int64(len(content)) || out.Offset != int64(len(content)) ||
				out.Rows != int64(bytes.Count(content, []byte{'\n'})) {
				t.Fatalf("incorrect full result: %+v", out)
			}
		})
	}
}

func TestSmallBudgetsResumeAcrossManyInvocations(t *testing.T) {
	content := bytes.Repeat([]byte("first\nsecond\nlast-byte-\x00\xff"), 40000)
	f := fixture(t, content)
	r := validRequest()
	r.LimitBytes = 17003 // Cross both SHA block and log record boundaries.
	clock, _ := fakeClock(nil)
	invocations := 0
	for {
		previous := r.Offset
		out, err := process(r, f, clock)
		if err != nil {
			t.Fatal(err)
		}
		invocations++
		if out.ReadBytes < 1 || out.ReadBytes > r.LimitBytes || out.Offset != previous+out.ReadBytes {
			t.Fatalf("budget/progress violation: %+v", out)
		}
		if out.Complete {
			want := sha256.Sum256(content)
			if out.SHA256 == nil || *out.SHA256 != hex.EncodeToString(want[:]) ||
				out.Rows != int64(bytes.Count(content, []byte{'\n'})) {
				t.Fatalf("resumed stream differs: %+v", out)
			}
			break
		}
		if out.SHA256 != nil {
			t.Fatal("partial stream exposed a full digest")
		}
		r.Offset, r.Rows, r.State = out.Offset, out.Rows, &out.State
	}
	if invocations < 20 {
		t.Fatal("fixture did not require sustained resume")
	}
}

func TestEmptyAndAlreadyCompleteResume(t *testing.T) {
	content := []byte("done\n")
	f := fixture(t, content)
	clock, _ := fakeClock(nil)
	out, err := process(validRequest(), f, clock)
	if err != nil {
		t.Fatal(err)
	}
	r := validRequest()
	r.Offset, r.Rows, r.State = out.Offset, out.Rows, &out.State
	completed, err := process(r, f, clock)
	if err != nil || !completed.Complete || completed.ReadBytes != 0 || completed.SHA256 == nil || *completed.SHA256 != *out.SHA256 {
		t.Fatalf("EOF resume: %+v %v", completed, err)
	}
}

func TestByteAndTimeBudgets(t *testing.T) {
	content := bytes.Repeat([]byte("x\n"), chunkSize*4)
	for _, limit := range []int64{1, chunkSize - 1, chunkSize + 13} {
		r := validRequest()
		r.LimitBytes = limit
		clock, _ := fakeClock(nil)
		out, err := process(r, fixture(t, content), clock)
		if err != nil || out.Complete || out.ReadBytes != limit || out.SHA256 != nil {
			t.Fatalf("byte budget %d: %+v %v", limit, out, err)
		}
	}
	r := validRequest()
	r.MaxSeconds, r.RateBytesPerSecond = 1, chunkSize/2
	clock, now := fakeClock(nil)
	started := *now
	out, err := process(r, fixture(t, content), clock)
	if err != nil || out.Complete || out.SHA256 != nil || out.ReadBytes != chunkSize || now.Sub(started) != time.Second {
		t.Fatalf("time/rate budget: %+v elapsed %s err %v", out, now.Sub(started), err)
	}
}

func TestFinalChunkIsRateLimited(t *testing.T) {
	r := validRequest()
	r.RateBytesPerSecond = 512
	clock, now := fakeClock(nil)
	started := *now
	out, err := process(r, fixture(t, bytes.Repeat([]byte{'a'}, 100)), clock)
	if err != nil || !out.Complete || now.Sub(started) != 100*time.Second/512 {
		t.Fatalf("small files bypassed rate limit: %+v elapsed %s err %v", out, now.Sub(started), err)
	}
}

func TestReadAfterInterruptionUsesSerializedPrefix(t *testing.T) {
	content := bytes.Repeat([]byte("row\n"), chunkSize)
	f := fixture(t, content)
	r := validRequest()
	r.LimitBytes = 12345
	clock, _ := fakeClock(nil)
	first, err := process(r, f, clock)
	if err != nil || first.Complete {
		t.Fatalf("first slice %+v %v", first, err)
	}
	// A new file object simulates the next process; its initial offset is zero.
	f2, err := os.Open(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer f2.Close()
	r = validRequest()
	r.State, r.Offset, r.Rows = &first.State, first.Offset, first.Rows
	last, err := process(r, f2, clock)
	want := sha256.Sum256(content)
	if err != nil || !last.Complete || last.SHA256 == nil || *last.SHA256 != hex.EncodeToString(want[:]) {
		t.Fatalf("interrupted stream: %+v %v", last, err)
	}
}

func TestBadStateAndOffsetRejected(t *testing.T) {
	f := fixture(t, []byte("abc\nlonger"))
	r := validRequest()
	r.LimitBytes = 3
	clock, _ := fakeClock(nil)
	good, err := process(r, f, clock)
	if err != nil {
		t.Fatal(err)
	}
	state, _ := base64.StdEncoding.DecodeString(good.State)
	for name, mutate := range map[string]func([]byte) []byte{
		"magic":                func(s []byte) []byte { s[0] = 'x'; return s },
		"size":                 func(s []byte) []byte { return s[:len(s)-1] },
		"counter":              func(s []byte) []byte { binary.BigEndian.PutUint64(s[len(s)-8:], 4); return s },
		"noncanonical_padding": func(s []byte) []byte { s[4+32+12] = 9; return s },
	} {
		t.Run(name, func(t *testing.T) {
			bad := base64.StdEncoding.EncodeToString(mutate(bytes.Clone(state)))
			r = validRequest()
			r.Offset, r.Rows, r.State = good.Offset, good.Rows, &bad
			_, err := process(r, f, clock)
			requireCode(t, err, "invalid_state")
		})
	}
	r = validRequest()
	r.Offset = 100
	_, err = process(r, f, clock)
	requireCode(t, err, "invalid_offset")
	bad := "not-base64!"
	r = validRequest()
	r.State = &bad
	_, err = process(r, f, clock)
	requireCode(t, err, "invalid_state")
}

func TestFileChangesDuringReadNeverReturnAResult(t *testing.T) {
	for _, change := range []string{"append", "truncate", "rewrite", "chmod"} {
		t.Run(change, func(t *testing.T) {
			content := bytes.Repeat([]byte("row\n"), chunkSize)
			f := fixture(t, content)
			changed := false
			clock, _ := fakeClock(func() {
				if changed {
					return
				}
				changed = true
				var err error
				switch change {
				case "append":
					_, err = f.WriteAt([]byte{'x'}, int64(len(content)))
				case "truncate":
					err = f.Truncate(3)
				case "rewrite":
					_, err = f.WriteAt([]byte("evil"), 0)
				case "chmod":
					err = f.Chmod(0400)
				}
				if err != nil {
					t.Fatal(err)
				}
			})
			r := validRequest()
			r.MaxSeconds, r.RateBytesPerSecond = 1, chunkSize/2
			out, err := process(r, f, clock)
			requireCode(t, err, "file_changed")
			if out.State != "" || out.SHA256 != nil || out.ReadBytes != 0 {
				t.Fatal("changed file returned a reusable checkpoint")
			}
		})
	}
}

func TestNonRegularDescriptorRejected(t *testing.T) {
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	clock, _ := fakeClock(nil)
	for _, f := range []*os.File{dir, r} {
		_, err = process(validRequest(), f, clock)
		requireCode(t, err, "regular_file_required")
	}
	closed := fixture(t, nil)
	_ = closed.Close()
	_, err = process(validRequest(), closed, clock)
	requireCode(t, err, "file_stat_failed")
}

func TestStrictInputValidation(t *testing.T) {
	data, _ := json.Marshal(validRequest())
	if _, err := parseRequest(bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"schema", "state", "offset", "rows", "limit_bytes", "max_seconds", "rate_bytes_per_second"} {
		t.Run("required_"+field, func(t *testing.T) {
			var raw map[string]any
			_ = json.Unmarshal(data, &raw)
			delete(raw, field)
			bad, _ := json.Marshal(raw)
			_, err := parseRequest(bytes.NewReader(bad))
			requireCode(t, err, "invalid_input")
		})
	}
	for name, bad := range map[string]string{
		"empty": "", "object": "[]", "oversize": strings.Repeat(" ", maxInput+1),
		"suffix": string(data) + "{}", "duplicate": strings.Replace(string(data), "\"schema\":1", "\"schema\":1,\"schema\":1", 1),
		"unknown":        strings.Replace(string(data), "\"schema\":1", "\"schema\":1,\"surprise\":1", 1),
		"float":          strings.Replace(string(data), "\"offset\":0", "\"offset\":0.5", 1),
		"negative":       strings.Replace(string(data), "\"offset\":0", "\"offset\":-1", 1),
		"null_int":       strings.Replace(string(data), "\"offset\":0", "\"offset\":null", 1),
		"false_int":      strings.Replace(string(data), "\"offset\":0", "\"offset\":false", 1),
		"wrong_schema":   strings.Replace(string(data), "\"schema\":1", "\"schema\":2", 1),
		"limit_low":      strings.Replace(string(data), "\"limit_bytes\":1073741824", "\"limit_bytes\":0", 1),
		"limit_high":     strings.Replace(string(data), "\"limit_bytes\":1073741824", "\"limit_bytes\":1073741825", 1),
		"seconds_low":    strings.Replace(string(data), "\"max_seconds\":60", "\"max_seconds\":0", 1),
		"seconds_high":   strings.Replace(string(data), "\"max_seconds\":60", "\"max_seconds\":61", 1),
		"rate_low":       strings.Replace(string(data), "\"rate_bytes_per_second\":67108864", "\"rate_bytes_per_second\":0", 1),
		"rate_high":      strings.Replace(string(data), "\"rate_bytes_per_second\":67108864", "\"rate_bytes_per_second\":67108865", 1),
		"rows_gt_offset": strings.Replace(string(data), "\"rows\":0", "\"rows\":1", 1),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseRequest(strings.NewReader(bad))
			requireCode(t, err, "invalid_input")
		})
	}
	_, err := parseRequest(strings.NewReader(strings.Replace(string(data), "\"offset\":0", "\"offset\":1", 1)))
	requireCode(t, err, "invalid_state")
}

func TestCLIArgumentsAndErrorsNeverEchoInput(t *testing.T) {
	data, _ := json.Marshal(validRequest())
	for _, args := range [][]string{nil, {"--help"}, {"--fd=0"}, {"--fd=-1"}, {"--fd=3", "extra"}, {"--fd=999999999"}, {"--fd=/secret"}, {"--fd=+3"}} {
		var out bytes.Buffer
		if run(args, bytes.NewReader(data), &out) != 1 || out.String() != "{\"schema\":1,\"error\":\"invalid_arguments\"}\n" {
			t.Fatalf("unsafe CLI response %v %q", args, out.String())
		}
	}
	var out bytes.Buffer
	if run([]string{"--fd=999999"}, strings.NewReader("secret-password"), &out) != 1 || strings.Contains(out.String(), "secret") {
		t.Fatalf("input echoed: %q", out.String())
	}
}

func TestCLIWithInheritedDescriptor(t *testing.T) {
	content := []byte("line one\nline two\n")
	f := fixture(t, content)
	fd, err := syscall.Dup(int(f.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(validRequest())
	var output bytes.Buffer
	if run([]string{"--fd=" + strconv.Itoa(fd)}, bytes.NewReader(data), &output) != 0 {
		t.Fatalf("CLI failed: %s", output.String())
	}
	var out response
	if err = json.NewDecoder(&output).Decode(&out); err != nil || !out.Complete || out.SHA256 == nil || out.Rows != 2 {
		t.Fatalf("CLI result: %+v %v", out, err)
	}
}

func FuzzRequestValidation(f *testing.F) {
	good, _ := json.Marshal(validRequest())
	f.Add(good)
	f.Add([]byte(`{"schema":1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseRequest(bytes.NewReader(data))
	})
}
