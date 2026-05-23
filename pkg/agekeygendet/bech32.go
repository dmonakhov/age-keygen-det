package agekeygendet

import (
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcutil/bech32"
)

// encodeBech32 encodes raw bytes as classical bech32 (NOT bech32m)
// with the given HRP. btcsuite's bech32.Encode does not apply
// BIP-173's 90-character length limit on the encode path; the limit
// is only checked when decoding via bech32.Decode. Our matching
// decodeBech32 uses bech32.DecodeNoLimit so the PQ recipient
// (~1959 characters, encoding a 1216-byte X-Wing public key) round-
// trips successfully. See age PR #452/#453 for upstream discussion.
//
// The HRP is lowercased before passing to the bech32 library; if
// uppercase is true, the whole returned string is uppercased.
// Bech32 forbids mixed-case strings, so the entire string is either
// all-upper (age identities, by convention) or all-lower (age
// recipients).
func encodeBech32(hrp string, payload []byte, uppercase bool) (string, error) {
	conv, err := bech32.ConvertBits(payload, 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("bech32: convertbits 8->5: %w", err)
	}
	s, err := bech32.Encode(strings.ToLower(hrp), conv)
	if err != nil {
		return "", fmt.Errorf("bech32: encode: %w", err)
	}
	if uppercase {
		return strings.ToUpper(s), nil
	}
	return s, nil
}

// decodeBech32 decodes a bech32 string (any length), returning the
// (lowercased) HRP and the 8-bit-aligned payload bytes.
func decodeBech32(s string) (hrp string, payload []byte, err error) {
	hrp, conv, err := bech32.DecodeNoLimit(s)
	if err != nil {
		return "", nil, fmt.Errorf("bech32: decode: %w", err)
	}
	payload, err = bech32.ConvertBits(conv, 5, 8, false)
	if err != nil {
		return "", nil, fmt.Errorf("bech32: convertbits 5->8: %w", err)
	}
	return hrp, payload, nil
}
