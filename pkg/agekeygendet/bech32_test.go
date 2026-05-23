package agekeygendet

import (
	"bytes"
	"strings"
	"testing"
)

// TestBech32LongHRP validates that the chosen bech32 library accepts
// the 18-character HRP "AGE-SECRET-KEY-PQ-" used by age PQ identities.
// This is the critical early-validation task from design-draft sec 9
// (decision 1): if this test fails, we need a different bech32
// library before committing to anything else.
func TestBech32LongHRP(t *testing.T) {
	hrp := "AGE-SECRET-KEY-PQ-"
	payload := bytes.Repeat([]byte{0xab}, 32)

	encoded, err := encodeBech32(hrp, payload, true)
	if err != nil {
		t.Fatalf("encodeBech32 with long HRP failed: %v", err)
	}
	if !strings.HasPrefix(encoded, "AGE-SECRET-KEY-PQ-1") {
		t.Errorf("expected prefix AGE-SECRET-KEY-PQ-1, got: %q", encoded)
	}

	gotHRP, gotPayload, err := decodeBech32(encoded)
	if err != nil {
		t.Fatalf("decodeBech32 round-trip failed: %v", err)
	}
	if gotHRP != strings.ToLower(hrp) {
		t.Errorf("HRP round-trip mismatch: got %q, want %q", gotHRP, strings.ToLower(hrp))
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Errorf("payload round-trip mismatch: got %x, want %x", gotPayload, payload)
	}
}

// TestBech32LongString validates that the no-limit encode path works
// for strings far longer than BIP-173's 90-char limit. The PQ
// recipient encodes a 1216-byte X-Wing public key, producing a ~1959-
// character bech32 string. We simulate this with 1216 bytes of dummy
// data and HRP "age1pq".
func TestBech32LongString(t *testing.T) {
	hrp := "age1pq"
	payload := bytes.Repeat([]byte{0xcd}, 1216)

	encoded, err := encodeBech32(hrp, payload, false)
	if err != nil {
		t.Fatalf("encodeBech32 with long payload failed: %v", err)
	}
	if len(encoded) < 1900 {
		t.Errorf("expected encoded string >= 1900 chars, got %d", len(encoded))
	}
	if !strings.HasPrefix(encoded, "age1pq1") {
		t.Errorf("expected prefix age1pq1, got first 16 chars: %q", encoded[:16])
	}

	gotHRP, gotPayload, err := decodeBech32(encoded)
	if err != nil {
		t.Fatalf("decodeBech32 round-trip on long string failed: %v", err)
	}
	if gotHRP != hrp {
		t.Errorf("HRP round-trip mismatch: got %q, want %q", gotHRP, hrp)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Errorf("payload round-trip mismatch on long string")
	}
}
