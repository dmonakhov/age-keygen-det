package agekeygendet

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// classicTestVectors hold the static expected outputs for known
// seeds. The expected strings are filled in after the first run of
// the test; once locked, they become a permanent contract -
// breaking them breaks every existing user's vault.
//
// To (re-)generate: run `go test -run TestDeriveClassicSnapshot -v`
// and copy the printed values into the expected fields.
var classicTestVectors = []struct {
	name          string
	seedHex       string
	wantIdentity  string
	wantRecipient string
}{
	{
		name:          "zero-seed",
		seedHex:       "0000000000000000000000000000000000000000000000000000000000000000",
		wantIdentity:  "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ8H00W3",
		wantRecipient: "age19ljhmg68e43yx9fgm2k9lwefquc0la5y4lzvlshdjzv47kxt8d6qr9vf4p",
	},
	{
		name:          "all-ones-seed",
		seedHex:       "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		wantIdentity:  "AGE-SECRET-KEY-1LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLS9FV78X",
		wantRecipient: "age1s37q6tph2g60xe0xvz24rparwddq7asn69sf6wn2fkx98t42tg3qvgcz2x",
	},
}

func TestDeriveClassic(t *testing.T) {
	for _, tc := range classicTestVectors {
		t.Run(tc.name, func(t *testing.T) {
			seed, err := hex.DecodeString(tc.seedHex)
			if err != nil {
				t.Fatalf("decode seed: %v", err)
			}

			gotID, gotRcpt, err := deriveClassic(seed)
			if err != nil {
				t.Fatalf("deriveClassic: %v", err)
			}

			if !strings.HasPrefix(gotID, "AGE-SECRET-KEY-1") {
				t.Errorf("identity missing HRP: %q", gotID)
			}
			if !strings.HasPrefix(gotRcpt, "age1") {
				t.Errorf("recipient missing HRP: %q", gotRcpt)
			}

			if tc.wantIdentity != "" && gotID != tc.wantIdentity {
				t.Errorf("identity mismatch:\n got: %s\nwant: %s", gotID, tc.wantIdentity)
			}
			if tc.wantRecipient != "" && gotRcpt != tc.wantRecipient {
				t.Errorf("recipient mismatch:\n got: %s\nwant: %s", gotRcpt, tc.wantRecipient)
			}
		})
	}
}

// TestDeriveClassicSnapshot prints the derived identities and
// recipients for the static test vectors. Used to (re-)generate the
// expected values when bootstrapping or after a deliberate change.
//
// Run with: go test -run TestDeriveClassicSnapshot -v
func TestDeriveClassicSnapshot(t *testing.T) {
	for _, tc := range classicTestVectors {
		seed, err := hex.DecodeString(tc.seedHex)
		if err != nil {
			t.Fatalf("decode seed: %v", err)
		}
		id, rcpt, err := deriveClassic(seed)
		if err != nil {
			t.Fatalf("deriveClassic %q: %v", tc.name, err)
		}
		t.Logf("\nname: %s\n  seed:      %s\n  identity:  %s\n  recipient: %s",
			tc.name, tc.seedHex, id, rcpt)
	}
}

// TestDeriveClassicRoundTrip checks that decoding the produced
// identity and recipient yields the original seed and a 32-byte
// public key respectively.
func TestDeriveClassicRoundTrip(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, 32)
	id, rcpt, err := deriveClassic(seed)
	if err != nil {
		t.Fatalf("deriveClassic: %v", err)
	}

	_, gotSeed, err := decodeBech32(id)
	if err != nil {
		t.Fatalf("decode identity: %v", err)
	}
	if !bytes.Equal(gotSeed, seed) {
		t.Errorf("decoded identity payload != seed: got %x, want %x", gotSeed, seed)
	}

	_, gotPub, err := decodeBech32(rcpt)
	if err != nil {
		t.Fatalf("decode recipient: %v", err)
	}
	if len(gotPub) != 32 {
		t.Errorf("decoded recipient payload should be 32 bytes, got %d", len(gotPub))
	}
}

// TestDeriveClassicSeedLength rejects non-32-byte seeds.
func TestDeriveClassicSeedLength(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		_, _, err := deriveClassic(bytes.Repeat([]byte{0}, n))
		if err == nil {
			t.Errorf("expected error for seed length %d, got nil", n)
		}
	}
}
