# Design draft - age-keygen-det

This document captures the design assumptions and decisions that the
implementation refers to. It is the in-repo source of truth for
"why does this code do what it does"; commit messages and code
comments cite section numbers here rather than scattering rationale
through history.

The document is a draft. Sections may grow with implementation but
their numbering is stable - it is referenced from code and tests.

---

## 1. Goal

Convert a 32-byte uniform seed into a deterministic
[age](https://age-encryption.org/v1) identity. Output mirrors stock
`age-keygen`, so existing age tooling (`age-keygen -y`, `age -d`,
`age -r`) works against the result without modification.

Two key types are supported:

- **Classic** (X25519). HRP `AGE-SECRET-KEY-`. Compatible with
  every age release since v1.0 (2021).
- **Post-quantum** (X-Wing, HPKE-MLKEM768-X25519). HRP
  `AGE-SECRET-KEY-PQ-`. Compatible with age v1.3.0+ (Dec 2025).

The same seed always produces the same identity. The recipient
(public key) appears in the output as a `# public key:` comment;
it is also recoverable from the identity at any time via stock
`age-keygen -y`.

## 2. Background

- **age classic identity** = `bech32("AGE-SECRET-KEY-", scalar32)`
  for any 32 uniform bytes (X25519 clamps internally).
  Recipient = `bech32("age", X25519(scalar32, BASEPOINT))`.
- **age PQ identity** = `bech32("AGE-SECRET-KEY-PQ-", seed32)`;
  X-Wing internally SHAKE256-expands the 32-byte seed.
  Recipient = `bech32("age1pq", X-Wing.PublicKey(seed32))`.
- **`age-keygen` output format** (what we mirror):

  ```
  # created: 2024-01-01T00:00:00Z
  # public key: age1...
  AGE-SECRET-KEY-1...
  ```

  The first two lines are comments; only the third (identity) is
  load-bearing. `age-keygen -y` regenerates the recipient by
  reading the third line.

## 3. Scope

In scope:

- One host-side binary `age-keygen-det` and library
  `pkg/agekeygendet`.
- Reads a 32-byte hex seed, emits an age identity file.
- Output format compatible with `age-keygen -y` for recipient
  recovery.
- Reproducible static build.

Out of scope:

- Any BIP-32 / BIP-85 derivation, path-formatting helpers, or
  per-project naming conventions. The user supplies the 32-byte
  seed from a separate tool (typically a hardware wallet).
- Recipient-only output, identity verification, batch derivation -
  all jobs for stock age tooling or scripting around it.
- Any UI beyond the CLI.

## 4. Library API

```go
package agekeygendet

type KeyType int
const (
    KeyTypeClassic KeyType = iota
    KeyTypePQ
)

type DerivedIdentity struct {
    Identity  string // bech32: "AGE-SECRET-KEY-..."
    Recipient string // bech32: "age1..." or "age1pq1..."
    Type      KeyType
}

// DeriveFromSeed derives a deterministic age identity from a
// 32-byte uniform seed. The seed source is not assumed.
func DeriveFromSeed(seed []byte, keyType KeyType) (*DerivedIdentity, error)
```

That is the entire public API.

## 5. CLI design

```
age-keygen-det -type pq|classic [-hex-file PATH | -hex-fd N]
               [-label TEXT] [-o FILE | --output FILE]
```

### 5.1 Seed input

The 32-byte seed is read from exactly one of three sources:

1. **`-hex-file PATH`**: regular file (whitespace stripped).
2. **`-hex-fd N`**: already-open file descriptor (process
   substitution, here-strings).
3. **Default**: prompt on `/dev/tty` with no echo, mirroring
   `age -p`'s passphrase reader.

All sources normalize identically: whitespace stripped, then
validated as exactly 64 hex characters.

The seed is NEVER accepted as a command-line argument; passing
a secret on the command line leaks it to shell history, process
listing (`ps`, `/proc/<pid>/cmdline`), and any logs that capture
invoked commands.

### 5.2 Output

The output mirrors stock `age-keygen`:

```
# label: <text>          (only if -label is given)
# public key: <RECIPIENT>
<IDENTITY>
```

Lines starting with `#` are comments; stock age tools (`age -d`,
`age-keygen -y`) ignore them. The third line is the load-bearing
identity.

A `# created:` timestamp like `age-keygen` produces is
deliberately omitted: it would defeat byte-stable determinism
(same seed -> same file, run after run).

#### Label content convention

When `-label TEXT` is given, the text is written verbatim as a
`# label: TEXT` comment. The label is **publishable** — it
shares a file with the recipient and gets distributed to anyone
the recipient does.

Recommended content: **master XFP + BIP-85 derivation path**.

    -label "<xfp-hex> m/83696968'/128169'/32'/<index>'"

Where:

- **XFP** (master fingerprint) is the first 4 bytes of
  `HASH160(master-pubkey)`, 8 lowercase hex characters. It is
  the standard public identifier Bitcoin wallets, descriptors,
  and PSBTs already use to distinguish wallets without revealing
  the seed. Compute once from the xprv (never from the
  mnemonic).
- The BIP-85 path tells the reader which slot of which
  application produced this seed. Combined with the XFP it
  uniquely identifies the key.

Example: `627ef3a6 m/83696968'/128169'/32'/0'`.

The label MUST NOT contain mnemonic words, seed bytes, or any
value derived from them. It lands verbatim in a file you intend
to publish; treat the label like the recipient itself. See
sec 8 (decision 7) for the reasoning.

### 5.3 Flags

| Flag | Description |
|------|-------------|
| `-type pq\|classic` | Key flavour. Required. |
| `-hex-file PATH` | Read seed from FILE (whitespace stripped). |
| `-hex-fd N` | Read seed from open file descriptor N. |
| `-label TEXT` | Add a `# label: TEXT` comment line. See sec 5.2 ("Label content convention") for what to put here. |
| `-o FILE`, `--output FILE` | Write to FILE (mode 0600) instead of stdout. |

### 5.4 Recovering the recipient

There is no verify or recipient-only subcommand. To recover the
recipient from an identity, use stock age:

```sh
$ age-keygen -y identity.txt
age1...
```

To verify a claimed recipient matches an identity, compare the
output of `age-keygen -y` to the claimed string.

## 6. Test strategy

### 6.1 Static test vectors

`pkg/agekeygendet/testdata/vectors.yaml`: `(seed_hex, type) ->
(identity, recipient)`. Once locked, these are a permanent
contract; breaking them breaks every existing user's vault.

### 6.2 Cross-validation against stock age

For every vector:

1. Pipe the identity to `age-keygen -y`.
2. Assert the printed recipient byte-equals the recipient stored
   in the vector.

Skipped if `age-keygen` is not in PATH; `make verify` requires it
and fails loudly otherwise.

### 6.3 Round-trip encryption test

For at least one vector per flavour:

```
echo "<plaintext>" | age -r "$RECIPIENT" -o test.age
age -d -i identity.txt test.age    # must match the plaintext
```

Guards against bech32-encoding bugs that pass `age-keygen -y`
(which only recomputes the recipient, not the keypair end-to-end).

## 7. Reproducible builds and archival

- `CGO_ENABLED=0` + `-trimpath -ldflags="-buildid= -s -w"`. The
  binary is statically linked; same source on same Go toolchain
  produces byte-identical output.
- `make all` cross-compiles linux/{amd64,arm64} +
  darwin/{amd64,arm64}.
- `make archive` bundles source + binaries + vectors into a
  tarball with `--sort=name --mtime=@<commit-time>` for
  tarball-level reproducibility. Intended for cold storage
  alongside the user's seed backup.

## 8. Decisions made

1. **Bech32 library: long-HRP and long-string support.** The PQ
   recipient encodes a 1216-byte X-Wing public key, yielding a
   ~1959-character bech32 string - far above BIP-173's 90-char
   limit. The identity HRP `AGE-SECRET-KEY-PQ-` is also longer
   than some libraries expect.
   **Resolved.** `github.com/btcsuite/btcd/btcutil/bech32` has no
   length limit on the encode path; `DecodeNoLimit` handles the
   long strings. Classical bech32, NOT bech32m.

2. **Recipient computation: in-process.** Classic via
   `golang.org/x/crypto/curve25519`; PQ via
   `filippo.io/mlkem768/xwing`. The recipient is also emitted as
   a `# public key:` comment in the output so the user can copy
   it without re-running anything; stock `age-keygen -y` agrees.

3. **`age-keygen -y` on PQ identities.** Verified during
   implementation: stock age v1.3.1 returns the matching
   recipient when given an `AGE-SECRET-KEY-PQ-1...` identity.
   Cross-validation in sec 6.2 relies on this.

4. **Secret input mechanism.** The seed is read from
   `/dev/tty` (no echo), `-hex-file`, or `-hex-fd` - never from
   a command-line argument. CLI args leak to shell history,
   process listing, and logs.

5. **No `# created:` timestamp.** `age-keygen` prints one;
   `age-keygen-det` omits it. Determinism trumps mimicry: a
   timestamp would make the same seed produce different output
   on different runs, defeating the entire purpose of the tool.

6. **No verify / recipient-only / bip85-path / batch
   subcommands.** Stock `age-keygen -y` recovers the recipient
   from any identity this tool emits, including PQ. BIP-85 path
   conventions are an upstream concern, not this tool's. Single
   binary, single mode of operation; everything else is yours
   to script.

7. **`-label` content: master XFP + BIP-85 path; never
   seed-derived.** Initial README draft used demonstration
   labels like `"BIP-85 hex/32/0"` and `"all-all-all/0"`. The
   latter outright leaked partial mnemonic words into a file
   we explicitly tell the user to publish. Even with a
   well-known test mnemonic, that pattern teaches the wrong
   practice.
   **Resolved.** The recommended label content (sec 5.2,
   "Label content convention") is `<xfp-hex> <BIP-85 path>`.
   The XFP (master fingerprint) is the same public identifier
   Bitcoin wallets, descriptors, and PSBTs already publish; it
   uniquely identifies a wallet without revealing the seed.
   Combined with the BIP-85 path it tells future-you which
   wallet and which slot produced an identity file, traceable
   without exposing anything secret.

## 9. References

- [age v1 spec](https://age-encryption.org/v1)
- [age-keygen source (output format)](https://github.com/FiloSottile/age/blob/main/cmd/age-keygen/keygen.go)
- [C2SP age spec](https://github.com/C2SP/C2SP/blob/main/age.md)
- [filippo.io/age godoc](https://pkg.go.dev/filippo.io/age)
- [filippo.io/mlkem768/xwing godoc](https://pkg.go.dev/filippo.io/mlkem768/xwing)
- [RFC 7748 (Curve25519)](https://datatracker.ietf.org/doc/rfc7748/)
- [draft-connolly-cfrg-xwing-kem-10](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/)
- [FIPS 203 (ML-KEM)](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf)
- [BIP-173 (bech32)](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki)
