package agekeygendet

import (
	"fmt"

	"golang.org/x/crypto/curve25519"
)

const (
	hrpClassicIdentity  = "AGE-SECRET-KEY-"
	hrpClassicRecipient = "age"
)

// deriveClassic computes a classic X25519 age identity and recipient
// from a 32-byte uniform seed. The seed is used directly as the
// X25519 scalar; curve25519.X25519 performs RFC 7748 clamping
// internally.
func deriveClassic(seed []byte) (identity, recipient string, err error) {
	if len(seed) != 32 {
		return "", "", fmt.Errorf("seed must be 32 bytes, got %d", len(seed))
	}

	pub, err := curve25519.X25519(seed, curve25519.Basepoint)
	if err != nil {
		return "", "", fmt.Errorf("X25519: %w", err)
	}

	identity, err = encodeBech32(hrpClassicIdentity, seed, true)
	if err != nil {
		return "", "", fmt.Errorf("encode identity: %w", err)
	}
	recipient, err = encodeBech32(hrpClassicRecipient, pub, false)
	if err != nil {
		return "", "", fmt.Errorf("encode recipient: %w", err)
	}
	return identity, recipient, nil
}
