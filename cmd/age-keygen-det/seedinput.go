package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"

	"golang.org/x/term"
)

// readSeedHex reads a 32-byte hex seed from exactly one of:
//   - /dev/tty (interactive, no echo) - the default when neither
//     --hex-file nor --hex-fd is given
//   - --hex-file PATH (regular file)
//   - --hex-fd N (already-open file descriptor)
//
// All sources are normalized identically: whitespace stripped,
// result must be exactly 64 hex characters.
//
// The seed is NEVER accepted on the command line. See design-draft
// sec 5.1 and sec 9 (decision 5) for rationale.
func readSeedHex(hexFile string, hexFD int, stderr io.Writer) ([]byte, error) {
	sources := 0
	if hexFile != "" {
		sources++
	}
	if hexFD >= 0 {
		sources++
	}
	if sources > 1 {
		return nil, fmt.Errorf("specify only one of --hex-file or --hex-fd (or neither for /dev/tty prompt)")
	}

	var raw string
	var err error
	switch {
	case hexFile != "":
		data, err := os.ReadFile(hexFile)
		if err != nil {
			return nil, fmt.Errorf("read --hex-file %q: %w", hexFile, err)
		}
		raw = string(data)
	case hexFD >= 0:
		raw, err = readFD(hexFD)
		if err != nil {
			return nil, err
		}
	default:
		raw, err = promptHexTTY(stderr)
		if err != nil {
			return nil, err
		}
	}
	return parseHexSeed(raw)
}

func readFD(fd int) (string, error) {
	f := os.NewFile(uintptr(fd), fmt.Sprintf("hex-fd/%d", fd))
	if f == nil {
		return "", fmt.Errorf("--hex-fd %d is not a valid open file descriptor", fd)
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return "", fmt.Errorf("read --hex-fd %d: %w", fd, err)
	}
	return string(data), nil
}

func promptHexTTY(stderr io.Writer) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("/dev/tty unavailable (use --hex-file or --hex-fd for non-interactive): %w", err)
	}
	defer tty.Close()
	fmt.Fprint(tty, "Enter 32-byte seed (64 hex chars, no echo): ")
	secret, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	if err != nil {
		return "", fmt.Errorf("read /dev/tty: %w", err)
	}
	return string(secret), nil
}

func parseHexSeed(raw string) ([]byte, error) {
	clean := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, raw)
	if len(clean) != 64 {
		return nil, fmt.Errorf("seed must be exactly 64 hex chars after whitespace stripping (got %d)", len(clean))
	}
	seed, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %w", err)
	}
	return seed, nil
}
