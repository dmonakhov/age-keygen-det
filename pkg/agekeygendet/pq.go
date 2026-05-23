package agekeygendet

import (
	"fmt"

	"filippo.io/mlkem768/xwing"
)

const (
	hrpPQIdentity  = "AGE-SECRET-KEY-PQ-"
	hrpPQRecipient = "age1pq"
)

// derivePQ computes a post-quantum (X-Wing / HPKE-MLKEM768-X25519)
// age identity and recipient from a 32-byte uniform seed.
//
// The seed is used directly as the X-Wing private-key seed; X-Wing
// internally SHAKE256-expands the seed into ML-KEM-768's (d, z) and
// the X25519 scalar. The 32-byte seed is therefore the entire
// archived private key.
//
// The encapsulation key is 1216 bytes (= ML-KEM-768 1184-byte
// encapsulation key concatenated with a 32-byte X25519 public key),
// producing a bech32 recipient string roughly 1959 characters long.
func derivePQ(seed []byte) (identity, recipient string, err error) {
	if len(seed) != 32 {
		return "", "", fmt.Errorf("seed must be 32 bytes, got %d", len(seed))
	}

	dk, err := xwing.NewKeyFromSeed(seed)
	if err != nil {
		return "", "", fmt.Errorf("X-Wing: %w", err)
	}
	pub := dk.EncapsulationKey()

	identity, err = encodeBech32(hrpPQIdentity, seed, true)
	if err != nil {
		return "", "", fmt.Errorf("encode identity: %w", err)
	}
	recipient, err = encodeBech32(hrpPQRecipient, pub, false)
	if err != nil {
		return "", "", fmt.Errorf("encode recipient: %w", err)
	}
	return identity, recipient, nil
}
