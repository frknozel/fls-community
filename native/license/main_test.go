package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const installation = "c4d7e67d-1496-4b5f-bae2-6e2f846120a1"
const otherInstallation = "31c0bc70-cac1-492b-987a-92bc8ef11221"
const licenseID = "791cbded-297c-47b8-b487-cdfc43dfdb91"
const fixtureTime int64 = 1792810000

func fixture(t *testing.T) (ed25519.PrivateKey, map[string][]byte, Obj, Obj) {
	t.Helper()
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	license := Obj{"schema": 1, "kind": "license", "license_id": licenseID, "installation_id": installation, "revision": 1, "issued_at": fixtureTime - 600, "not_before": fixtureTime - 600, "expires_at": fixtureTime + 365*86400, "features": []string{"analysis", "api_polling", "config_comparison", "insights"}, "max_devices": 16}
	hash := sha256.Sum256(canonical(license))
	nonce := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	lease := Obj{"schema": 1, "kind": "lease", "installation_id": installation, "license_id": licenseID, "license_revision": 1, "license_sha256": hex.EncodeToString(hash[:]), "sequence": 1, "request_nonce": nonce, "issued_at": fixtureTime, "expires_at": fixtureTime + MaxOfflineSeconds}
	return priv, map[string][]byte{"fixture-only": pub}, license, lease
}
func sign(priv ed25519.PrivateKey, p Obj) []byte {
	raw := canonical(p)
	return canonical(Obj{"key_id": "fixture-only", "payload": base64.RawURLEncoding.EncodeToString(raw), "signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, raw))})
}
func mustStatus(t *testing.T, status Obj, wanted string) {
	t.Helper()
	if str(status, "status") != wanted {
		t.Fatalf("wanted %s got %v", wanted, status)
	}
}
func TestSignedLeaseDeadlineCoreAndAdvanced(t *testing.T) {
	priv, keys, l, lease := fixture(t)
	state := Obj{"pending_nonce": lease["request_nonce"]}
	s, next, e := evaluate("commercial", installation, fixtureTime, 100, "boot1", state, keys, sign(priv, l), sign(priv, lease), true)
	if e != nil {
		t.Fatal(e)
	}
	mustStatus(t, s, "active")
	if !featureAllowed(s, "analysis", fixtureTime) || !featureAllowed(s, "api_polling", fixtureTime) {
		t.Fatal("valid signed lease did not allow advanced")
	}
	s, next, e = evaluate("commercial", installation, fixtureTime+MaxOfflineSeconds-1, 100+MaxOfflineSeconds-1, "boot1", next, keys, sign(priv, l), nil, true)
	if e != nil {
		t.Fatal(e)
	}
	mustStatus(t, s, "active")
	if number(s, "lease_expires_at") != fixtureTime+MaxOfflineSeconds {
		t.Fatal("reception extended deadline")
	}
	s, _, _ = evaluate("commercial", installation, fixtureTime+MaxOfflineSeconds, 100+MaxOfflineSeconds, "boot1", next, keys, sign(priv, l), nil, true)
	mustStatus(t, s, "offline_limit_exceeded")
	for _, feature := range coreFeatures {
		if !featureAllowed(s, feature, fixtureTime+MaxOfflineSeconds) {
			t.Fatalf("core feature blocked: %s", feature)
		}
	}
	for _, feature := range advancedFeatures {
		if featureAllowed(s, feature, fixtureTime+MaxOfflineSeconds) {
			t.Fatalf("advanced feature allowed after expiry: %s", feature)
		}
	}
	if featureAllowed(nil, "unknown", fixtureTime) {
		t.Fatal("unknown feature allowed")
	}
}
func TestProductionNeverPretendsServiceAvailable(t *testing.T) {
	priv, keys, l, lease := fixture(t)
	s, next, e := evaluate("commercial", installation, fixtureTime, 100, "boot1", Obj{"pending_nonce": lease["request_nonce"]}, keys, sign(priv, l), sign(priv, lease), ServiceReady)
	if e != nil {
		t.Fatal(e)
	}
	mustStatus(t, s, "activation_server_unconfigured")
	if s["advanced_allowed"] != false || next["lease_sequence"] != nil {
		t.Fatal("unconfigured activation accepted a lease")
	}
	s, next, e = evaluate("development", installation, fixtureTime, 100, "boot1", Obj{}, nil, nil, nil, ServiceReady)
	if e != nil {
		t.Fatal(e)
	}
	mustStatus(t, s, "development")
	if !featureAllowed(s, "analysis", fixtureTime) || s["lease_expires_at"] != nil || next["lease_sequence"] != nil {
		t.Fatal("development mode minted a lease or blocked")
	}
}
func TestProtocolRejectsSignatureBindingAndLeaseOver72Hours(t *testing.T) {
	priv, keys, l, lease := fixture(t)
	cases := []struct {
		name   string
		change func(Obj, Obj)
		code   string
	}{
		{"other installation", func(l, p Obj) { l["installation_id"] = otherInstallation }, "installation_mismatch"},
		{"long lease", func(l, p Obj) { p["expires_at"] = fixtureTime + MaxOfflineSeconds + 1 }, "lease_time"},
		{"future lease", func(l, p Obj) { p["issued_at"] = fixtureTime + 6 }, "lease_time"},
		{"wrong nonce", func(l, p Obj) { p["request_nonce"] = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)) }, "lease_nonce"},
		{"wrong license", func(l, p Obj) { p["license_sha256"] = strings.Repeat("0", 64) }, "lease_license_mismatch"},
		{"schema boolean", func(l, p Obj) { l["schema"] = true }, "payload_kind"},
		{"unknown field", func(l, p Obj) { l["exec"] = "anything" }, "license_fields"},
		{"unknown feature", func(l, p Obj) { l["features"] = []string{"exec"} }, "license_features"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, b := copyObj(l), copyObj(lease)
			c.change(a, b)
			s, _, e := evaluate("commercial", installation, fixtureTime, 100, "boot1", Obj{"pending_nonce": lease["request_nonce"]}, keys, sign(priv, a), sign(priv, b), true)
			if e != nil {
				t.Fatal(e)
			}
			if s["advanced_allowed"] != false {
				t.Fatal("invalid license/lease allowed")
			}
			if str(s, "status") != c.code {
				found := false
				for _, x := range s["errors"].([]string) {
					found = found || x == c.code
				}
				if !found {
					t.Fatalf("wanted %s got %v", c.code, s)
				}
			}
		})
	}
	signed := sign(priv, l)
	badKeys := map[string][]byte{"fixture-only": bytes.Repeat([]byte{1}, 32)}
	_, _, _, e := licenseDocument(signed, badKeys, installation, fixtureTime)
	if e == nil || e.Error() != "signature_invalid" {
		t.Fatal("wrong issuer signature accepted")
	}
	_, _, _, e = licenseDocument(signed, map[string][]byte{}, installation, fixtureTime)
	if e == nil || e.Error() != "issuer_unknown" {
		t.Fatal("unknown issuer accepted")
	}
}
func TestReplayAndFailedAttemptCannotExtendLease(t *testing.T) {
	priv, keys, l, lease := fixture(t)
	_, state, _ := evaluate("commercial", installation, fixtureTime, 100, "boot1", Obj{"pending_nonce": lease["request_nonce"]}, keys, sign(priv, l), sign(priv, lease), true)
	attempt := copyObj(lease)
	attempt["expires_at"] = fixtureTime + MaxOfflineSeconds - 60
	s, next, _ := evaluate("commercial", installation, fixtureTime+10, 110, "boot1", state, keys, sign(priv, l), sign(priv, attempt), true)
	mustStatus(t, s, "active_lease_preserved")
	if number(s, "lease_expires_at") != fixtureTime+MaxOfflineSeconds || str(next, "lease_digest") != str(state, "lease_digest") {
		t.Fatal("replay changed accepted lease")
	}
	s, _, _ = evaluate("commercial", installation, fixtureTime+11, 111, "boot1", next, keys, sign(priv, l), []byte(`{"error":"timeout"}`), true)
	mustStatus(t, s, "active_lease_preserved")
	if number(s, "lease_expires_at") != fixtureTime+MaxOfflineSeconds {
		t.Fatal("failed response extended lease")
	}
	stale := copyObj(lease)
	stale["sequence"] = 0
	_, _, _, e := leaseDocument(sign(priv, stale), keys, installation, l, str(lease, "license_sha256"), fixtureTime)
	if e == nil {
		t.Fatal("sequence zero accepted")
	}
	next["lease_sequence"] = 2
	_, e = acceptLease(sign(priv, lease), keys, installation, l, str(lease, "license_sha256"), fixtureTime, next)
	if e == nil || e.Error() != "lease_replay" {
		t.Fatal("old sequence accepted")
	}
}
func TestClockRollbackAndStaleStatus(t *testing.T) {
	priv, keys, l, lease := fixture(t)
	_, state, _ := evaluate("commercial", installation, fixtureTime, 100, "boot1", Obj{"pending_nonce": lease["request_nonce"]}, keys, sign(priv, l), sign(priv, lease), true)
	s, _, _ := evaluate("commercial", installation, fixtureTime-6, 101, "boot2", state, keys, sign(priv, l), sign(priv, lease), true)
	mustStatus(t, s, "clock_rollback")
	s, _, _ = evaluate("commercial", installation, fixtureTime+10, 130, "boot1", state, keys, sign(priv, l), sign(priv, lease), true)
	mustStatus(t, s, "clock_rollback")
	s, _, _ = evaluate("commercial", installation, fixtureTime, 100, "boot1", Obj{"pending_nonce": lease["request_nonce"]}, keys, sign(priv, l), sign(priv, lease), true)
	if featureAllowed(s, "analysis", fixtureTime+121) || featureAllowed(s, "analysis", fixtureTime-1) {
		t.Fatal("stale or future commercial status trusted")
	}
	for _, f := range coreFeatures {
		if !featureAllowed(nil, f, fixtureTime) {
			t.Fatalf("status failure blocked %s", f)
		}
	}
}
func TestStrictJSONLimitsCanonicalAndCLI(t *testing.T) {
	for _, raw := range [][]byte{[]byte(`{"a":1,"a":2}`), []byte(`{"n":1.0}`), []byte(`{"n":1e3}`), []byte(`{} {}`), {0xff}, bytes.Repeat([]byte{' '}, MaxDocument+1)} {
		if _, e := strictJSON(raw, MaxDocument); e == nil {
			t.Fatalf("invalid JSON accepted %q", raw[:min(20, len(raw))])
		}
	}
	var out bytes.Buffer
	if n := run([]string{"check", "archive_export"}, strings.NewReader(""), &out); n != 0 {
		t.Fatal("core CLI requires a license")
	}
	out.Reset()
	if n := run([]string{"check", "run-shell"}, strings.NewReader(""), &out); n != 64 {
		t.Fatal("unknown feature accepted")
	}
	out.Reset()
	if n := run([]string{"evaluate"}, strings.NewReader(`{"mode":"development","extra":1}`), &out); n != 65 {
		t.Fatal("unknown request accepted")
	}
	out.Reset()
	if n := run([]string{"evaluate"}, bytes.NewReader(bytes.Repeat([]byte{'a'}, 262145)), &out); n != 65 {
		t.Fatal("oversized input accepted")
	}
	pub, _, _, _ := fixture(t)
	_ = pub
	if _, e := rootFile(filepath.Join(t.TempDir(), "not-here"), 1024); e == nil {
		t.Fatal("untrusted parent trusted")
	}
	path := filepath.Join(t.TempDir(), "status")
	if e := os.WriteFile(path, []byte(`{}`), 0666); e != nil {
		t.Fatal(e)
	}
	if _, e := rootFile(path, 1024); e == nil {
		t.Fatal("writable status accepted")
	}
	request := Obj{"mode": "development", "installation_id": installation, "now": fixtureTime, "boottime": 100, "boot_id": "boot1", "state": Obj{}, "issuer_keys": Obj{}, "license": "", "lease": ""}
	out.Reset()
	if n := run([]string{"evaluate"}, bytes.NewReader(canonical(request)), &out); n != 0 {
		t.Fatal(out.String())
	}
	var response Obj
	if json.Unmarshal(out.Bytes(), &response) != nil {
		t.Fatal("invalid result")
	}
}

func TestChallengeUsesSignedLicenseWithoutExtendingDeadline(t *testing.T) {
	priv, keys, license, lease := fixture(t)
	keyInput := Obj{}
	for k, v := range keys {
		keyInput[k] = base64.RawURLEncoding.EncodeToString(v)
	}
	request := Obj{"mode": "commercial", "installation_id": installation, "now": fixtureTime, "boottime": 100, "boot_id": "boot1", "state": Obj{"lease_sequence": 9, "lease_issued_at": fixtureTime - 100}, "issuer_keys": keyInput, "license": string(sign(priv, license)), "lease": ""}
	var output bytes.Buffer
	if exit := run([]string{"prepare"}, bytes.NewReader(canonical(request)), &output); exit != 0 {
		t.Fatal(output.String())
	}
	decoded, e := strictJSON(output.Bytes(), 262144)
	if e != nil {
		t.Fatal(e)
	}
	response := decoded.(Obj)
	challenge := response["challenge"].(Obj)
	state := response["state"].(Obj)
	if number(state, "lease_sequence") != 9 || number(state, "lease_issued_at") != fixtureTime-100 || state["accepted_lease"] != nil {
		t.Fatal("challenge changed lease or entitlement")
	}
	if _, e = b64(challenge["request_nonce"], 32); e != nil {
		t.Fatal("invalid nonce")
	}
	if str(state, "pending_nonce") != str(challenge, "request_nonce") {
		t.Fatal("nonce not persisted")
	}
	if str(challenge, "license_sha256") != str(lease, "license_sha256") || str(challenge, "installation_id") != installation {
		t.Fatal("challenge not bound to signed license")
	}
	license["installation_id"] = otherInstallation
	request["license"] = string(sign(priv, license))
	output.Reset()
	if exit := run([]string{"prepare"}, bytes.NewReader(canonical(request)), &output); exit != 65 {
		t.Fatal("wrong installation challenge issued")
	}
	request["license"] = string(sign(priv, copyObj(license)))
	request["state"] = Obj{"installation_id": otherInstallation}
	output.Reset()
	if exit := run([]string{"evaluate"}, bytes.NewReader(canonical(request)), &output); exit != 65 {
		t.Fatal("other installation state accepted")
	}
}

func TestCommercialBuildRejectsDevelopmentExemption(t *testing.T) {
	original := buildChannel
	buildChannel = "commercial"
	defer func() { buildChannel = original }()
	if _, _, e := evaluate("development", installation, fixtureTime, 100, "boot1", Obj{}, nil, nil, nil, false); e == nil || e.Error() != "development_disabled" {
		t.Fatal("commercial binary accepted development policy")
	}
	if featureAllowed(Obj{"schema": 1, "mode": "development", "status": "development", "checked_at": fixtureTime, "advanced_allowed": true}, "analysis", fixtureTime) {
		t.Fatal("commercial binary trusted development status")
	}
	if !featureAllowed(nil, "archive_export", fixtureTime) {
		t.Fatal("commercial build blocked core")
	}
}
