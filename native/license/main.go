// FLS license protocol. This binary contains public-key verification only.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

const MaxDocument = 32768
const MaxOfflineSeconds int64 = 72 * 60 * 60
const ClockTolerance int64 = 5

// Set only with the future, implemented and reviewed activation client release.
// No network service is available in this version; there is no ping fallback.
const ServiceReady = false

// Commercial images are built separately; changing policy cannot enable the
// development exemption in their native worker guards.
var buildChannel = "development"

var coreFeatures = []string{"collector", "ingest", "integrity", "timestamp", "archive_export", "archive_verify", "archive_download", "retention", "authentication", "settings"}
var advancedFeatures = []string{"analysis", "api_polling", "config_comparison", "insights"}
var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var keyPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Obj = map[string]any

func fail(code string) error { return errors.New(code) }
func contains(items []string, key string) bool {
	for _, s := range items {
		if s == key {
			return true
		}
	}
	return false
}
func sorted(items []string) []string { x := append([]string{}, items...); sort.Strings(x); return x }
func integer(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case int:
		return int64(n), true
	case json.Number:
		x, e := n.Int64()
		return x, e == nil && x >= 0 && x <= 9007199254740991
	}
	return 0, false
}
func number(o Obj, k string) int64 { n, _ := integer(o[k]); return n }
func str(o Obj, k string) string   { s, _ := o[k].(string); return s }
func strictJSON(raw []byte, limit int) (any, error) {
	if len(raw) == 0 || len(raw) > limit {
		return nil, fail("document_size")
	}
	if !utf8.Valid(raw) {
		return nil, fail("invalid_json")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value func(int) (any, error)
	value = func(depth int) (any, error) {
		if depth > 24 {
			return nil, fail("json_depth")
		}
		t, e := d.Token()
		if e != nil {
			return nil, fail("invalid_json")
		}
		if del, ok := t.(json.Delim); ok {
			switch del {
			case '{':
				o := Obj{}
				for d.More() {
					k, e := d.Token()
					if e != nil {
						return nil, fail("invalid_json")
					}
					s, ok := k.(string)
					if !ok {
						return nil, fail("invalid_json")
					}
					if _, exists := o[s]; exists {
						return nil, fail("duplicate_json_key")
					}
					v, e := value(depth + 1)
					if e != nil {
						return nil, e
					}
					o[s] = v
				}
				end, e := d.Token()
				if e != nil || end != json.Delim('}') {
					return nil, fail("invalid_json")
				}
				return o, nil
			case '[':
				a := []any{}
				for d.More() {
					v, e := value(depth + 1)
					if e != nil {
						return nil, e
					}
					a = append(a, v)
				}
				end, e := d.Token()
				if e != nil || end != json.Delim(']') {
					return nil, fail("invalid_json")
				}
				return a, nil
			}
			return nil, fail("invalid_json")
		}
		if n, ok := t.(json.Number); ok {
			if _, valid := integer(n); !valid {
				return nil, fail("number_type")
			}
		}
		return t, nil
	}
	v, e := value(0)
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, fail("invalid_json")
	}
	return v, nil
}
func canonical(v any) []byte {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if e.Encode(v) != nil {
		return nil
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}
func exact(o Obj, keys ...string) bool {
	if len(o) != len(keys) {
		return false
	}
	for _, k := range keys {
		if _, ok := o[k]; !ok {
			return false
		}
	}
	return true
}
func b64(v any, size int) ([]byte, error) {
	s, ok := v.(string)
	if !ok || len(s) == 0 {
		return nil, fail("base64")
	}
	b, e := base64.RawURLEncoding.Strict().DecodeString(s)
	if e != nil || base64.RawURLEncoding.EncodeToString(b) != s {
		return nil, fail("base64")
	}
	if size >= 0 && len(b) != size {
		return nil, fail("base64_length")
	}
	return b, nil
}
func document(raw []byte, keys map[string][]byte, kind string) (Obj, string, Obj, error) {
	v, e := strictJSON(raw, MaxDocument)
	if e != nil {
		return nil, "", nil, e
	}
	o, ok := v.(Obj)
	if !ok || !exact(o, "key_id", "payload", "signature") {
		return nil, "", nil, fail("envelope_fields")
	}
	k := str(o, "key_id")
	if !keyPattern.MatchString(k) {
		return nil, "", nil, fail("key_id")
	}
	public := keys[k]
	if len(public) != ed25519.PublicKeySize {
		return nil, "", nil, fail("issuer_unknown")
	}
	payload, e := b64(o["payload"], -1)
	if e != nil {
		return nil, "", nil, e
	}
	v, e = strictJSON(payload, 16384)
	if e != nil {
		return nil, "", nil, e
	}
	p, ok := v.(Obj)
	if !ok {
		return nil, "", nil, fail("payload_kind")
	}
	if !bytes.Equal(canonical(p), payload) {
		return nil, "", nil, fail("payload_not_canonical")
	}
	signature, e := b64(o["signature"], ed25519.SignatureSize)
	if e != nil {
		return nil, "", nil, e
	}
	if !ed25519.Verify(public, payload, signature) {
		return nil, "", nil, fail("signature_invalid")
	}
	if number(p, "schema") != 1 || str(p, "kind") != kind {
		return nil, "", nil, fail("payload_kind")
	}
	hash := sha256.Sum256(payload)
	return p, hex.EncodeToString(hash[:]), o, nil
}
func positive(p Obj, keys ...string) bool {
	for _, k := range keys {
		n, ok := integer(p[k])
		if !ok || n <= 0 {
			return false
		}
	}
	return true
}
func licenseDocument(raw []byte, keys map[string][]byte, id string, now int64) (Obj, string, Obj, error) {
	p, h, o, e := document(raw, keys, "license")
	if e != nil {
		return nil, "", nil, e
	}
	if !exact(p, "schema", "kind", "license_id", "installation_id", "revision", "issued_at", "not_before", "expires_at", "features", "max_devices") {
		return nil, "", nil, fail("license_fields")
	}
	if !uuidPattern.MatchString(str(p, "license_id")) || !uuidPattern.MatchString(str(p, "installation_id")) {
		return nil, "", nil, fail("identifier")
	}
	if str(p, "installation_id") != id {
		return nil, "", nil, fail("installation_mismatch")
	}
	if !positive(p, "revision", "issued_at", "not_before", "expires_at", "max_devices") || number(p, "max_devices") > 1000000 {
		return nil, "", nil, fail("number_type")
	}
	issued, start, end := number(p, "issued_at"), number(p, "not_before"), number(p, "expires_at")
	if issued > start || start >= end || issued > now+ClockTolerance {
		return nil, "", nil, fail("license_time")
	}
	if now < start {
		return nil, "", nil, fail("license_not_yet_valid")
	}
	if now >= end {
		return nil, "", nil, fail("license_expired")
	}
	features, ok := p["features"].([]any)
	seen := map[string]bool{}
	if !ok || len(features) > len(advancedFeatures) {
		return nil, "", nil, fail("license_features")
	}
	for _, v := range features {
		s, ok := v.(string)
		if !ok || !contains(advancedFeatures, s) || seen[s] {
			return nil, "", nil, fail("license_features")
		}
		seen[s] = true
	}
	return p, h, o, nil
}
func leaseDocument(raw []byte, keys map[string][]byte, id string, license Obj, licenseHash string, now int64) (Obj, string, Obj, error) {
	p, h, o, e := document(raw, keys, "lease")
	if e != nil {
		return nil, "", nil, e
	}
	if !exact(p, "schema", "kind", "installation_id", "license_id", "license_revision", "license_sha256", "sequence", "request_nonce", "issued_at", "expires_at") {
		return nil, "", nil, fail("lease_fields")
	}
	if !uuidPattern.MatchString(str(p, "license_id")) || !uuidPattern.MatchString(str(p, "installation_id")) {
		return nil, "", nil, fail("identifier")
	}
	if str(p, "installation_id") != id {
		return nil, "", nil, fail("installation_mismatch")
	}
	if !positive(p, "license_revision", "sequence", "issued_at", "expires_at") {
		return nil, "", nil, fail("number_type")
	}
	if str(p, "license_id") != str(license, "license_id") || number(p, "license_revision") != number(license, "revision") || str(p, "license_sha256") != licenseHash {
		return nil, "", nil, fail("lease_license_mismatch")
	}
	if _, e = b64(p["request_nonce"], 32); e != nil {
		return nil, "", nil, e
	}
	start, end := number(p, "issued_at"), number(p, "expires_at")
	if start >= end || end > start+MaxOfflineSeconds || start > now+ClockTolerance || start < number(license, "not_before") {
		return nil, "", nil, fail("lease_time")
	}
	if end > number(license, "expires_at") {
		return nil, "", nil, fail("lease_exceeds_license")
	}
	return p, h, o, nil
}
func copyObj(o Obj) Obj {
	x := Obj{}
	for k, v := range o {
		x[k] = v
	}
	return x
}
func clockCheck(state Obj, now, boottime int64, bootID string) error {
	if now <= 0 {
		return fail("number_type")
	}
	if now+ClockTolerance < number(state, "wall_high_water") {
		return fail("clock_rollback")
	}
	if str(state, "boot_id") == bootID && bootID != "" {
		delta := boottime - number(state, "boottime")
		if delta < -ClockTolerance {
			return fail("clock_rollback")
		}
		if delta < 0 {
			delta = 0
		}
		if now+ClockTolerance < number(state, "wall_seen")+delta {
			return fail("clock_rollback")
		}
	}
	return nil
}
func acceptLease(raw []byte, keys map[string][]byte, id string, license Obj, hash string, now int64, state Obj) (Obj, error) {
	p, digest, envelope, e := leaseDocument(raw, keys, id, license, hash, now)
	if e != nil {
		return nil, e
	}
	sequence := number(state, "lease_sequence")
	if number(p, "sequence") < sequence {
		return nil, fail("lease_replay")
	}
	if number(p, "sequence") == sequence {
		if digest != str(state, "lease_digest") {
			return nil, fail("lease_replay")
		}
	} else {
		if str(p, "request_nonce") != str(state, "pending_nonce") {
			return nil, fail("lease_nonce")
		}
		if number(p, "issued_at") < number(state, "lease_issued_at") {
			return nil, fail("lease_replay")
		}
		state["lease_sequence"] = number(p, "sequence")
		state["lease_digest"] = digest
		state["lease_issued_at"] = number(p, "issued_at")
		state["accepted_lease"] = envelope
		delete(state, "pending_nonce")
	}
	return p, nil
}
func evaluate(mode, id string, now, boottime int64, bootID string, state Obj, keys map[string][]byte, licenseRaw, leaseRaw []byte, serviceReady bool) (Obj, Obj, error) {
	if mode != "development" && mode != "commercial" {
		return nil, nil, fail("policy_mode")
	}
	if mode == "development" && buildChannel != "development" {
		return nil, nil, fail("development_disabled")
	}
	if buildChannel != "development" && buildChannel != "commercial" {
		return nil, nil, fail("build_channel")
	}

	if !uuidPattern.MatchString(id) {
		return nil, nil, fail("identifier")
	}
	next := copyObj(state)
	faults := []string{}
	features := []string{}
	if mode == "development" {
		features = sorted(advancedFeatures)
	}
	result := Obj{"schema": 1, "installation_id": id, "mode": mode, "checked_at": now, "service_configured": serviceReady, "enforcement": mode == "commercial", "status": "development", "advanced_allowed": mode == "development", "features": features, "license_id": nil, "license_expires_at": nil, "lease_issued_at": nil, "lease_expires_at": nil, "offline_remaining_seconds": nil, "max_devices": nil, "errors": faults, "build_channel": buildChannel}
	setError := func(e error) {
		result["status"] = e.Error()
		if !contains(faults, e.Error()) {
			faults = append(faults, e.Error())
		}
		result["errors"] = faults
	}
	if e := clockCheck(state, now, boottime, bootID); e != nil {
		faults = append(faults, e.Error())
		result["errors"] = faults
		if mode == "commercial" {
			setError(e)
			return result, next, nil
		}
	}
	high := number(state, "wall_high_water")
	if now > high {
		high = now
	}
	next["schema"] = 1
	next["installation_id"] = id
	next["wall_high_water"] = high
	next["wall_seen"] = now
	next["boottime"] = boottime
	next["boot_id"] = bootID
	if mode == "development" {
		return result, next, nil
	}
	if !serviceReady {
		result["status"] = "activation_server_unconfigured"
		return result, next, nil
	}
	if len(licenseRaw) == 0 {
		setError(fail("license_missing"))
		return result, next, nil
	}
	license, hash, _, e := licenseDocument(licenseRaw, keys, id, now)
	if e != nil {
		setError(e)
		return result, next, nil
	}
	if number(license, "issued_at") < number(state, "license_issued_at") || (str(license, "license_id") == str(state, "license_id") && number(license, "revision") < number(state, "license_revision")) {
		setError(fail("license_replay"))
		return result, next, nil
	}
	next["license_id"] = license["license_id"]
	next["license_revision"] = license["revision"]
	next["license_issued_at"] = license["issued_at"]
	result["license_id"] = license["license_id"]
	result["license_expires_at"] = license["expires_at"]
	result["max_devices"] = license["max_devices"]
	var lease Obj
	if len(leaseRaw) > 0 {
		lease, e = acceptLease(leaseRaw, keys, id, license, hash, now, next)
		if e != nil {
			faults = append(faults, e.Error())
			result["errors"] = faults
		}
	}
	if lease == nil {
		if accepted, ok := next["accepted_lease"].(Obj); ok {
			lease, _, _, e = leaseDocument(canonical(accepted), keys, id, license, hash, now)
			if e != nil {
				setError(e)
				return result, next, nil
			}
		}
	}
	if lease == nil {
		setError(fail("lease_missing"))
		return result, next, nil
	}
	deadline := number(lease, "expires_at")
	if end := number(license, "expires_at"); end < deadline {
		deadline = end
	}
	remaining := deadline - now
	if remaining < 0 {
		remaining = 0
	}
	result["lease_issued_at"] = lease["issued_at"]
	result["lease_expires_at"] = deadline
	result["offline_remaining_seconds"] = remaining
	if now >= deadline {
		setError(fail("offline_limit_exceeded"))
		return result, next, nil
	}
	result["status"] = "active"
	if len(faults) > 0 {
		result["status"] = "active_lease_preserved"
	}
	result["advanced_allowed"] = true
	result["features"] = license["features"]
	return result, next, nil
}
func featureAllowed(s Obj, feature string, now int64) bool {
	if contains(coreFeatures, feature) {
		return true
	}
	if !contains(advancedFeatures, feature) || s == nil || number(s, "schema") != 1 {
		return false
	}
	allowed, _ := s["advanced_allowed"].(bool)
	// Development installs are deliberately not commercial enforcement targets.
	// A stopped status timer is visible, but does not silently lock the pilot.
	if str(s, "mode") == "development" {
		return buildChannel == "development" && allowed && str(s, "status") == "development"
	}
	checked, ok := integer(s["checked_at"])
	if !ok || now < checked || now-checked > 120 {
		return false
	}
	service, _ := s["service_configured"].(bool)
	deadline, valid := integer(s["lease_expires_at"])
	if !valid || !service || !allowed || str(s, "mode") != "commercial" || !contains([]string{"active", "active_lease_preserved"}, str(s, "status")) || now >= deadline {
		return false
	}
	switch f := s["features"].(type) {
	case []any:
		for _, v := range f {
			if v == feature {
				return true
			}
		}
	case []string:
		return contains(f, feature)
	}
	return false
}
func rootFile(path string, limit int) ([]byte, error) {
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		fi, e := os.Lstat(parent)
		if e != nil || !fi.IsDir() || fi.Mode().Perm()&0022 != 0 {
			return nil, fail("status_permissions")
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			return nil, fail("status_permissions")
		}
		if parent == "/" {
			break
		}
	}
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, fail("status_unavailable")
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	fi, e := f.Stat()
	if e != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0022 != 0 || fi.Size() > int64(limit) || fi.Size() <= 0 {
		return nil, fail("status_permissions")
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || st.Nlink != 1 {
		return nil, fail("status_permissions")
	}
	b, e := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if e != nil || len(b) > limit {
		return nil, fail("status_unavailable")
	}
	return b, nil
}
func run(args []string, stdin io.Reader, stdout io.Writer) int {
	if len(args) == 2 && args[0] == "check" {
		feature := args[1]
		if !contains(coreFeatures, feature) && !contains(advancedFeatures, feature) {
			fmt.Fprintln(stdout, `{"allowed":false,"code":"unknown_feature"}`)
			return 64
		}
		if contains(coreFeatures, feature) {
			fmt.Fprintln(stdout, `{"allowed":true,"code":"core_unrestricted"}`)
			return 0
		}
		raw, e := rootFile("/var/lib/fls-license/status.json", 65536)
		var status Obj
		if e == nil {
			v, err := strictJSON(raw, 65536)
			if err == nil {
				status, _ = v.(Obj)
			}
		}
		allowed := featureAllowed(status, feature, time.Now().Unix())
		code := "advanced_denied"
		if allowed {
			code = "allowed"
		}
		json.NewEncoder(stdout).Encode(Obj{"allowed": allowed, "code": code})
		if allowed {
			return 0
		}
		return 78
	}
	if len(args) != 1 || (args[0] != "evaluate" && args[0] != "prepare") {
		fmt.Fprintln(stdout, `{"error":"usage"}`)
		return 64
	}
	raw, e := io.ReadAll(io.LimitReader(stdin, 262145))
	if e != nil || len(raw) > 262144 {
		fmt.Fprintln(stdout, `{"error":"request_size"}`)
		return 65
	}
	v, e := strictJSON(raw, 262144)
	r, ok := v.(Obj)
	if e != nil || !ok || !exact(r, "mode", "installation_id", "now", "boottime", "boot_id", "state", "issuer_keys", "license", "lease") {
		fmt.Fprintln(stdout, `{"error":"request_fields"}`)
		return 65
	}
	for _, key := range []string{"mode", "installation_id", "boot_id", "license", "lease"} {
		if _, ok := r[key].(string); !ok {
			fmt.Fprintln(stdout, `{"error":"request_types"}`)
			return 65
		}
	}
	state, ok := r["state"].(Obj)
	if !ok {
		fmt.Fprintln(stdout, `{"error":"state_fields"}`)
		return 65
	}
	allowedState := []string{"schema", "installation_id", "wall_high_water", "wall_seen", "boottime", "boot_id", "license_id", "license_revision", "license_issued_at", "lease_sequence", "lease_digest", "lease_issued_at", "accepted_lease", "pending_nonce"}
	for key, value := range state {
		if !contains(allowedState, key) {
			fmt.Fprintln(stdout, `{"error":"state_fields"}`)
			return 65
		}
		if contains([]string{"schema", "wall_high_water", "wall_seen", "boottime", "license_revision", "license_issued_at", "lease_sequence", "lease_issued_at"}, key) {
			if _, ok := integer(value); !ok {
				fmt.Fprintln(stdout, `{"error":"state_types"}`)
				return 65
			}
		}
	}
	keyInput, ok := r["issuer_keys"].(Obj)
	if !ok || len(keyInput) > 16 {
		fmt.Fprintln(stdout, `{"error":"issuer_keys"}`)
		return 65
	}
	keys := map[string][]byte{}
	for k, v := range keyInput {
		b, e := b64(v, 32)
		if !keyPattern.MatchString(k) || e != nil {
			fmt.Fprintln(stdout, `{"error":"issuer_keys"}`)
			return 65
		}
		keys[k] = b
	}
	now, valid := integer(r["now"])
	boot, validBoot := integer(r["boottime"])
	if !valid || !validBoot || now <= 0 || boot < 0 || len(str(r, "boot_id")) > 64 {
		fmt.Fprintln(stdout, `{"error":"request_time"}`)
		return 65
	}
	licenseRaw, leaseRaw := []byte(str(r, "license")), []byte(str(r, "lease"))
	if existing := str(state, "installation_id"); existing != "" && existing != str(r, "installation_id") {
		json.NewEncoder(stdout).Encode(Obj{"error": "state_installation_mismatch"})
		return 65
	}
	if args[0] == "prepare" {
		if e := clockCheck(state, now, boot, str(r, "boot_id")); e != nil {
			json.NewEncoder(stdout).Encode(Obj{"error": e.Error()})
			return 65
		}
		license, digest, _, err := licenseDocument(licenseRaw, keys, str(r, "installation_id"), now)
		if err != nil {
			json.NewEncoder(stdout).Encode(Obj{"error": err.Error()})
			return 65
		}
		if number(license, "issued_at") < number(state, "license_issued_at") || (str(license, "license_id") == str(state, "license_id") && number(license, "revision") < number(state, "license_revision")) {
			json.NewEncoder(stdout).Encode(Obj{"error": "license_replay"})
			return 65
		}
		nonce := make([]byte, 32)
		if _, err = rand.Read(nonce); err != nil {
			json.NewEncoder(stdout).Encode(Obj{"error": "nonce_unavailable"})
			return 70
		}
		next := copyObj(state)
		encoded := base64.RawURLEncoding.EncodeToString(nonce)
		next["pending_nonce"] = encoded
		json.NewEncoder(stdout).Encode(Obj{"state": next, "challenge": Obj{"schema": 1, "installation_id": str(r, "installation_id"), "license_id": str(license, "license_id"), "license_revision": number(license, "revision"), "license_sha256": digest, "sequence_floor": number(state, "lease_sequence"), "request_nonce": encoded}})
		return 0
	}
	status, next, e := evaluate(str(r, "mode"), str(r, "installation_id"), now, boot, str(r, "boot_id"), state, keys, licenseRaw, leaseRaw, ServiceReady)
	if e != nil {
		json.NewEncoder(stdout).Encode(Obj{"error": e.Error()})
		return 65
	}
	json.NewEncoder(stdout).Encode(Obj{"status": status, "state": next})
	return 0
}
func main() {
	if len(os.Args) == 2 && strings.TrimSpace(os.Args[1]) == "version" {
		fmt.Println("fls-license-core 1 protocol=1 channel=" + buildChannel + " service=unconfigured")
		return
	}
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout))
}
