// Package agekeygendet derives deterministic age identities from
// uniform 32-byte seeds.
//
// The package does not assume any particular source for the seed.
// BIP-85 HEX output, /dev/urandom, dice + hash, or any other uniform
// 32-byte source is equally valid as input.
//
// See design-draft.md in the repo root for the design rationale,
// API surface, security UX, and test strategy.
package agekeygendet

// KeyType selects which age identity flavour to derive.
type KeyType int

const (
	// KeyTypeClassic derives an X25519 age identity (HRP
	// AGE-SECRET-KEY-, recipient HRP age). Compatible with every
	// age release since v1.0.
	KeyTypeClassic KeyType = iota

	// KeyTypePQ derives an X-Wing (HPKE-MLKEM768-X25519) age
	// identity (HRP AGE-SECRET-KEY-PQ-, recipient HRP age1pq).
	// Requires age v1.3.0+ on the decrypting side.
	KeyTypePQ
)

// DerivedIdentity is the result of a DeriveFromSeed call.
type DerivedIdentity struct {
	// Identity is the bech32-encoded private key, e.g.
	// "AGE-SECRET-KEY-1..." or "AGE-SECRET-KEY-PQ-1...".
	Identity string

	// Recipient is the bech32-encoded public key, e.g.
	// "age1..." or "age1pq1...".
	Recipient string

	// Type is the key flavour requested.
	Type KeyType
}
