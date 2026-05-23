package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	zeroSeed            = "0000000000000000000000000000000000000000000000000000000000000000"
	zeroSeedClassicID   = "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ8H00W3"
	zeroSeedClassicRcpt = "age19ljhmg68e43yx9fgm2k9lwefquc0la5y4lzvlshdjzv47kxt8d6qr9vf4p"
)

func runCLI(t *testing.T, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	var stdoutBuf, stderrBuf bytes.Buffer
	exitCode = run(args, &stdoutBuf, &stderrBuf)
	return stdoutBuf.String(), stderrBuf.String(), exitCode
}

func writeSeedFile(t *testing.T, hexStr string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "seed.hex")
	if err := os.WriteFile(path, []byte(hexStr+"\n"), 0o600); err != nil {
		t.Fatalf("write seed file: %v", err)
	}
	return path
}

func TestVersion(t *testing.T) {
	stdout, _, code := runCLI(t, "-version")
	if code != 0 {
		t.Fatalf("version exit %d", code)
	}
	if !strings.Contains(stdout, "age-keygen-det v") {
		t.Errorf("version did not print expected banner: %q", stdout)
	}
}

// TestOutputFormatExact is the golden test for the identity-file
// output format (design-draft sec 5.2). Drift breaks downstream
// `age-keygen -y` round-trips.
func TestOutputFormatExact(t *testing.T) {
	seedFile := writeSeedFile(t, zeroSeed)
	stdout, _, code := runCLI(t, "-type", "classic", "-hex-file", seedFile)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	want := "# public key: " + zeroSeedClassicRcpt + "\n" + zeroSeedClassicID + "\n"
	if stdout != want {
		t.Errorf("output mismatch:\n got: %q\nwant: %q", stdout, want)
	}
}

func TestDeriveClassicHexFile(t *testing.T) {
	seedFile := writeSeedFile(t, zeroSeed)
	stdout, _, code := runCLI(t, "-type", "classic", "-hex-file", seedFile)
	if code != 0 {
		t.Fatalf("exit %d, stderr only", code)
	}
	if !strings.Contains(stdout, "# public key: "+zeroSeedClassicRcpt) {
		t.Errorf("expected `# public key:` line, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, zeroSeedClassicID) {
		t.Errorf("expected identity in output, got:\n%s", stdout)
	}
}

func TestDeriveWithLabel(t *testing.T) {
	seedFile := writeSeedFile(t, zeroSeed)
	stdout, _, code := runCLI(t, "-type", "classic", "-hex-file", seedFile, "-label", "my vault key")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(stdout, "# label: my vault key\n") {
		t.Errorf("expected label line, got:\n%s", stdout)
	}
	// Label line MUST precede the public-key line.
	if strings.Index(stdout, "# label:") > strings.Index(stdout, "# public key:") {
		t.Errorf("label should precede public key, got:\n%s", stdout)
	}
}

func TestDeriveOutputShort(t *testing.T) {
	seedFile := writeSeedFile(t, zeroSeed)
	tmp := filepath.Join(t.TempDir(), "key.txt")
	_, _, code := runCLI(t, "-type", "classic", "-hex-file", seedFile, "-o", tmp)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	data, err := os.ReadFile(tmp)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(data), zeroSeedClassicID) {
		t.Errorf("expected identity in file, got: %s", data)
	}
	st, err := os.Stat(tmp)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("expected mode 0600, got %o", st.Mode().Perm())
	}
}

func TestDeriveOutputLong(t *testing.T) {
	seedFile := writeSeedFile(t, zeroSeed)
	tmp := filepath.Join(t.TempDir(), "key.txt")
	_, _, code := runCLI(t, "-type", "classic", "-hex-file", seedFile, "--output", tmp)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if _, err := os.Stat(tmp); err != nil {
		t.Errorf("file not written: %v", err)
	}
}

func TestMissingType(t *testing.T) {
	seedFile := writeSeedFile(t, zeroSeed)
	_, stderr, code := runCLI(t, "-hex-file", seedFile)
	if code == 0 {
		t.Error("missing -type should fail")
	}
	if !strings.Contains(stderr, "-type is required") {
		t.Errorf("expected required-flag error, got: %s", stderr)
	}
}

func TestInvalidType(t *testing.T) {
	seedFile := writeSeedFile(t, zeroSeed)
	_, stderr, code := runCLI(t, "-type", "garbage", "-hex-file", seedFile)
	if code == 0 {
		t.Error("invalid -type should fail")
	}
	if !strings.Contains(stderr, "invalid -type") {
		t.Errorf("expected invalid-type error, got: %s", stderr)
	}
}

func TestAmbiguousInput(t *testing.T) {
	seedFile := writeSeedFile(t, zeroSeed)
	_, stderr, code := runCLI(t, "-type", "classic", "-hex-file", seedFile, "-hex-fd", "5")
	if code == 0 {
		t.Error("two input sources should fail")
	}
	if !strings.Contains(stderr, "only one of") {
		t.Errorf("expected ambiguous-input error, got: %s", stderr)
	}
}

func TestBadHexFile(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.hex")
	if err := os.WriteFile(bad, []byte("not-hex\n"), 0o600); err != nil {
		t.Fatalf("write bad file: %v", err)
	}
	_, stderr, code := runCLI(t, "-type", "classic", "-hex-file", bad)
	if code == 0 {
		t.Error("bad hex content should fail")
	}
	if !strings.Contains(stderr, "64 hex chars") && !strings.Contains(stderr, "invalid hex") {
		t.Errorf("expected hex validation error, got: %s", stderr)
	}
}

func TestHexFileWhitespaceStripping(t *testing.T) {
	noisy := filepath.Join(t.TempDir(), "noisy.hex")
	content := "  " + zeroSeed[:32] + "\n" + zeroSeed[32:] + "\n\n"
	if err := os.WriteFile(noisy, []byte(content), 0o600); err != nil {
		t.Fatalf("write noisy file: %v", err)
	}
	stdout, _, code := runCLI(t, "-type", "classic", "-hex-file", noisy)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(stdout, zeroSeedClassicID) {
		t.Errorf("expected zero-seed identity, got: %s", stdout)
	}
}

func TestDerivePQHexFile(t *testing.T) {
	seedFile := writeSeedFile(t, zeroSeed)
	stdout, _, code := runCLI(t, "-type", "pq", "-hex-file", seedFile)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(stdout, "AGE-SECRET-KEY-PQ-1") {
		t.Errorf("expected PQ identity prefix, got first 60 chars: %q", stdout[:60])
	}
	if !strings.Contains(stdout, "# public key: age1pq1") {
		t.Errorf("expected PQ recipient prefix in public-key line, got:\n%.80s", stdout)
	}
}
