package agekeygendet

import (
	"bytes"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type crossVector struct {
	Name      string `yaml:"name"`
	SeedHex   string `yaml:"seed_hex"`
	Type      string `yaml:"type"`
	Identity  string `yaml:"identity"`
	Recipient string `yaml:"recipient"`
}

func loadCrossVectors(t *testing.T) []crossVector {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "vectors.yaml"))
	if err != nil {
		t.Fatalf("read vectors.yaml: %v", err)
	}
	var vs []crossVector
	if err := yaml.Unmarshal(data, &vs); err != nil {
		t.Fatalf("parse vectors.yaml: %v", err)
	}
	if len(vs) == 0 {
		t.Fatal("no vectors loaded")
	}
	return vs
}

// TestVectorsMatchLibrary asserts that the YAML vectors agree with
// what the library currently computes. This is an internal-consistency
// check, independent of stock age. Runs without external dependencies.
func TestVectorsMatchLibrary(t *testing.T) {
	for _, v := range loadCrossVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			seed, err := hex.DecodeString(v.SeedHex)
			if err != nil {
				t.Fatalf("decode seed: %v", err)
			}
			var kt KeyType
			switch v.Type {
			case "classic":
				kt = KeyTypeClassic
			case "pq":
				kt = KeyTypePQ
			default:
				t.Fatalf("unknown type %q", v.Type)
			}
			got, err := DeriveFromSeed(seed, kt)
			if err != nil {
				t.Fatalf("DeriveFromSeed: %v", err)
			}
			if got.Identity != v.Identity {
				t.Errorf("identity mismatch:\n got: %s\nwant: %s", got.Identity, v.Identity)
			}
			if got.Recipient != v.Recipient {
				// PQ recipients are huge; show only first 80 chars on mismatch.
				t.Errorf("recipient mismatch:\n got: %s...\nwant: %s...",
					truncate(got.Recipient, 80), truncate(v.Recipient, 80))
			}
		})
	}
}

// TestCrossValidateAgeKeygen runs `age-keygen -y` on each vector's
// identity and asserts the printed recipient matches what we have
// stored. This is the canonical correctness check (design-draft
// sec 7.2): "stock age agrees with us about the recipient."
//
// Skipped if `age-keygen` is not in PATH. `make verify` calls
// `go test -run "Cross|RoundTrip"` and requires the binaries.
func TestCrossValidateAgeKeygen(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not in PATH; skipping (`make verify` requires it)")
	}
	for _, v := range loadCrossVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			cmd := exec.Command("age-keygen", "-y")
			cmd.Stdin = strings.NewReader(v.Identity)
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("age-keygen -y: %v (stderr if any: %s)", err, exitStderr(err))
			}
			got := strings.TrimSpace(string(out))
			if got != v.Recipient {
				t.Errorf("recipient mismatch for %s\n got: %s\nwant: %s",
					v.Name, truncate(got, 100), truncate(v.Recipient, 100))
			}
		})
	}
}

// TestRoundTripEncryption encrypts a known plaintext to the
// recipient and decrypts it with the identity, using stock age on
// both ends. Guards against bech32-encoding bugs that would slip
// past age-keygen -y (which only recomputes the recipient from the
// identity, not the keypair end-to-end).
//
// design-draft sec 7.3. One vector per flavour is sufficient.
func TestRoundTripEncryption(t *testing.T) {
	if _, err := exec.LookPath("age"); err != nil {
		t.Skip("age not in PATH; skipping (`make verify` requires it)")
	}
	vectors := loadCrossVectors(t)

	for _, kind := range []string{"classic", "pq"} {
		var v crossVector
		for _, candidate := range vectors {
			if candidate.Type == kind {
				v = candidate
				break
			}
		}
		if v.Name == "" {
			t.Fatalf("no %s vector found", kind)
		}

		t.Run(kind, func(t *testing.T) {
			plaintext := "hello round-trip from " + v.Name + "\n"

			encCmd := exec.Command("age", "-r", v.Recipient)
			encCmd.Stdin = strings.NewReader(plaintext)
			ciphertext, err := encCmd.Output()
			if err != nil {
				t.Fatalf("encrypt: %v (stderr: %s)", err, exitStderr(err))
			}

			keyPath := filepath.Join(t.TempDir(), "k.txt")
			if err := os.WriteFile(keyPath, []byte(v.Identity+"\n"), 0o600); err != nil {
				t.Fatalf("write key: %v", err)
			}

			decCmd := exec.Command("age", "-d", "-i", keyPath)
			decCmd.Stdin = bytes.NewReader(ciphertext)
			decrypted, err := decCmd.Output()
			if err != nil {
				t.Fatalf("decrypt: %v (stderr: %s)", err, exitStderr(err))
			}
			if string(decrypted) != plaintext {
				t.Errorf("plaintext mismatch:\n got: %q\nwant: %q", decrypted, plaintext)
			}
		})
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func exitStderr(err error) string {
	if ee, ok := err.(*exec.ExitError); ok {
		return string(ee.Stderr)
	}
	return ""
}
