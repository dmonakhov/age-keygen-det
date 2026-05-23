# age-keygen-det

Deterministic [age](https://age-encryption.org/v1) identity
derivation from a 32-byte uniform seed. Output mirrors stock
`age-keygen` — every existing age tool (`age-keygen -y`, `age -d`,
`age -r`) works against the result unchanged.

Two key types:

- **Classic age** (`age1...` / `AGE-SECRET-KEY-1...`, X25519) -
  compatible with every age release since v1.0 (2021).
- **Post-quantum age** (`age1pq1...` / `AGE-SECRET-KEY-PQ-1...`,
  HPKE-MLKEM768-X25519 / X-Wing) - compatible with age v1.3.0+
  (Dec 2024).

The same seed always produces the same identity.

## Why

People who already secure a BIP-39 mnemonic have, over the years,
built up a lot of practice around it: paper backups, metal plates,
geographic redundancy, seed-sharding schemes (SeedXOR, etc.), and
air-gapped hardware-wallet workflows.
[BIP-85](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki)
layers application-specific entropy derivation on top of that same
root, and any 32-byte output of BIP-85's HEX application is a
valid input for `age-keygen-det`. So the "where do I back up my
age key" problem reduces to the already-solved "where do I back
up my BIP-39 seed" problem - no new physical procedure, no new
envelope, no parallel sharding plan.

A second reason this tool exists: age cannot mix classic and PQ
recipients in a single ciphertext. Cold-storage and receive-only
workflows therefore need both flavours derived from a single root
of trust.

## Install

```sh
go install github.com/dmonakhov/age-keygen-det/cmd/age-keygen-det@latest
```

Or build from source:

```sh
git clone https://github.com/dmonakhov/age-keygen-det
cd age-keygen-det
make build        # one binary for the host
make all          # cross-compile linux/{amd64,arm64} + darwin/{amd64,arm64}
make archive      # tarball for cold storage (source + binaries + vectors)
```

Binaries are statically linked (`CGO_ENABLED=0`) and built
reproducibly: rebuilding from the same source yields byte-identical
output.

## Usage

The 32-byte seed is **never** taken on the command line — passing
a secret via a flag leaks it to shell history, process listing
(`ps`, `/proc/<pid>/cmdline`), and any logs that capture commands.
Three safe sources:

```sh
# 1. Interactive: prompts on /dev/tty (no echo, like `age -p`)
age-keygen-det -type classic

# 2. From a file (chmod 0400 it; shred afterwards)
age-keygen-det -type classic -hex-file seed.txt

# 3. From an open file descriptor (no filesystem touch)
age-keygen-det -type pq -hex-fd 3 3< seed.txt
age-keygen-det -type pq -hex-fd 0 <<< "$SEED"
```

Output:

```
# public key: age19ljhmg68e43yx9fgm2k9lwefquc0la5y4lzvlshdjzv47kxt8d6qr9vf4p
AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ8H00W3
```

Write to a file (mode 0600) with `-o FILE` or `--output FILE`:

```sh
age-keygen-det -type classic -hex-file seed.txt -o vault.key
```

Add an annotation that ends up as a comment line:

```sh
age-keygen-det -type classic -hex-file seed.txt \
    -label "<MASTER-XFP> m/83696968'/128169'/32'/0'"
```

```
# label: 627ef3a6 m/83696968'/128169'/32'/0'
# public key: age1m0hh...
AGE-SECRET-KEY-1AG7W...
```

> **Best practice — what to put in `-label`:**
> The label ends up in a publishable identity file alongside the
> recipient. Treat it like the recipient: **safe to share,
> nothing seed-derived**. The combination that uniquely
> identifies a key without leaking secrets is the **master
> fingerprint** (XFP — first 4 bytes of `HASH160(master-pubkey)`,
> a public identifier used by Bitcoin wallets) plus the **BIP-85
> derivation path**. With those two strings you (and future-you)
> can tell two identity files apart and trace each back to which
> wallet and which slot produced it — without ever needing to
> see, type, or store the mnemonic. **Never** put the mnemonic,
> seed bytes, or anything derived from them into `-label`; it
> would land verbatim in a file you intend to publish.

The seed content is whitespace-tolerant: spaces, tabs, and
newlines are stripped before validating the result is exactly 64
hex characters.

### Worked example: BIP-85 → age

[BIP-85](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki)'s
HEX application (application number `128169'`) derives uniform
entropy at the path
`m/83696968'/128169'/{num_bytes}'/{index}'`. The 32-byte form is
exactly the input `age-keygen-det` consumes.

In a real deployment the BIP-85 derivation runs on an air-gapped
device (e.g. a ColdCard Q) and the device displays the 32-byte
result. To make the chain reproducible without hardware, this
example uses [bipsea](https://github.com/akarve/bipsea) (the
BIP-85 reference implementation) and the master `xprv` published
in the BIP-85 spec's HEX test vector. Anyone with `bipsea` and
`age-keygen-det` can reproduce these byte-for-byte.

```sh
# The master root xprv from BIP-85 spec sec "HEX" test vector.
XPRV="xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"

# Sanity: bipsea reproduces the spec's published HEX64 vector.
$ bipsea derive -a hex -n 64 -i 0 -x "$XPRV"
492db4698cf3b73a5a24998aa3e9d7fa96275d85724a91e71aa2d645442f878555d078fd1f1f67e368976f04137b1f7a0d19232136ca50c44614af72b5582a5c

# Derive 32 bytes at index 0 -> the seed we feed into age-keygen-det.
$ bipsea derive -a hex -n 32 -i 0 -x "$XPRV"
ea3ceb0b02ee8e587779c63f4b7b3a21e950a213f1ec53cab608d13e8796e6dc

# Pipe directly into age-keygen-det via FD 0 (no filesystem touch).
# The label uses the master XFP (627ef3a6 for the spec xprv) plus
# the BIP-85 derivation path - uniquely identifies the key
# without revealing the seed.
$ bipsea derive -a hex -n 32 -i 0 -x "$XPRV" | \
    age-keygen-det -type classic -hex-fd 0 \
                   -label "627ef3a6 m/83696968'/128169'/32'/0'"
# label: 627ef3a6 m/83696968'/128169'/32'/0'
# public key: age1m0hhzxelxsxnxm4ennvdpk75j8s7mn5w4tt3e4ntug5qx256wslqmdz8e9
AGE-SECRET-KEY-1AG7WKZCZA689SAMECCL5K7E6Y854PGSN78K98J4KPRGNAPUKUMWQWNNT4U

# Same seed, PQ flavour.
$ bipsea derive -a hex -n 32 -i 0 -x "$XPRV" | \
    age-keygen-det -type pq -hex-fd 0
# public key: age1pq185uujtjer5ruyuw0z2na47q34lt45ytunkwuwmve8j758gc9tyscstpzsxv22...
AGE-SECRET-KEY-PQ-1AG7WKZCZA689SAMECCL5K7E6Y854PGSN78K98J4KPRGNAPUKUMWQ5AN2M5

# Index 1 -> independent identity.
$ bipsea derive -a hex -n 32 -i 1 -x "$XPRV" | \
    age-keygen-det -type classic -hex-fd 0
# public key: age1qsm0j4tupku4juauk65qngcep5wx5du0ll0emgk977x7hv3wae4qadcuc0
AGE-SECRET-KEY-1UCX9EJYKCDM5ZHNDF0548CJD7665QRX6788VSSCYCE9FVKV8YQXQE4FK25
```

Replace `XPRV` with your own master key and the index with the
rotation slot you want. Note that the BIP-85 path *includes*
`num_bytes`, so HEX32 (`/32'/0'`) and HEX64 (`/64'/0'`) are
independent derivations — they are not related by truncation.

#### From a BIP-39 mnemonic

In practice you do not start with an `xprv`; you start with a
BIP-39 mnemonic that lives on paper or metal. The chain becomes
`mnemonic → BIP-32 xprv → BIP-85 HEX → age-keygen-det`.

> **Best practice — for demonstration only:**
> The example below runs the entire chain (`bipsea validate`,
> `bipsea xprv`, `bipsea derive`, and `age-keygen-det`) on one
> host. **Do not do this with a real mnemonic.** Anything that
> touches the mnemonic — `validate`, `xprv`, and `derive` —
> should run on an offline device (a hardware wallet like
> ColdCard Q, or a dedicated air-gapped computer). Only the
> final 32-byte hex output crosses the air gap to the warm
> host (transcribed, QR-scanned, or shuttled on a one-shot
> USB). The warm host running `age-keygen-det` never sees the
> mnemonic; it only re-encodes those 32 bytes as an age
> identity. Treat what follows as a learning aid you can run
> against a well-known test mnemonic, not a production
> workflow.

Using the well-known 12-word test mnemonic
`all all all all all all all all all all all all` (a valid
BIP-39 string used in many wallets' integration tests):

```sh
$ MNEMONIC="all all all all all all all all all all all all"

# BIP-39 mnemonic -> BIP-32 master xprv.
$ XPRV=$(bipsea validate -m "$MNEMONIC" | bipsea xprv)
$ echo "$XPRV"
xprv9s21ZrQH143K2rbkN6QpF6ZB3QQcyJA6aYbagMp6i8y831VVvpfcWNWqg5DM6GxSn66UDQUrgRgQEsLPZJC3APkPsQjxB7ndNMgj5R5HLmo

# BIP-85 HEX32/0 from that xprv.
$ bipsea derive -a hex -n 32 -i 0 -x "$XPRV"
1e280e343eec53287ea4a1997d7a74b9301c2d7179d27c14b772f8da5e351095

# Full chain into age-keygen-det. The label is the master XFP
# (5c9e228d - HASH160 of the master public key, computed once
# from the xprv, NEVER from the mnemonic) plus the BIP-85
# derivation path.
$ bipsea validate -m "$MNEMONIC" | bipsea xprv \
    | xargs -I {} bipsea derive -a hex -n 32 -i 0 -x {} \
    | age-keygen-det -type classic -hex-fd 0 \
                     -label "5c9e228d m/83696968'/128169'/32'/0'"
# label: 5c9e228d m/83696968'/128169'/32'/0'
# public key: age15k2lpn5z26c3q7hu68mu49d37v32cl9pjl2vs86sq70vwmk9jfyqxeltjq
AGE-SECRET-KEY-1RC5QUDP7A3FJSL4Y5XVH67N5HYCPCTT308F8C99HWTUD5H34ZZ2S2DRZK9
```

The same mnemonic + same path always produces the same identity —
that is the entire point. Memorize / metal-stamp the mnemonic; the
age identity is regenerable from it forever.

If your wallet uses a BIP-39 passphrase (the "25th word"), pass it
to `bipsea xprv -p <PASSPHRASE>`; the derived xprv changes
accordingly, and so does every downstream key.

### Recovering the recipient

There is no separate recipient or verify subcommand. Stock age
recovers the recipient from any identity file this tool writes:

```sh
$ age-keygen -y vault.key
age19ljhmg68e43yx9fgm2k9lwefquc0la5y4lzvlshdjzv47kxt8d6qr9vf4p
```

That same workflow works for the PQ flavour:

```sh
$ age-keygen-det -type pq -hex-file seed.txt -o vault.pq.key
$ age-keygen -y vault.pq.key
age1pq1...
```

## Security model

- **Identities are regenerable** from the seed - the seed is the
  entire backup. Delete the identity any time; the same input
  produces the same identity again.
- The seed is **never accepted on the command line**. Use
  `-hex-file`, `-hex-fd`, or the `/dev/tty` prompt.
- The tool **does not perform any BIP-32 / BIP-85 derivation
  internally**. Produce the 32-byte seed elsewhere (typically on
  an air-gapped device like a ColdCard Q) and supply it via one
  of the three input methods. The master seed never reaches the
  host this tool runs on.
- File output (`-o FILE`) is written with mode 0600.

## Cross-validation against stock age

```sh
make verify       # requires age v1.3.0+ in PATH
```

For every test vector, the harness pipes the identity to
`age-keygen -y` and asserts the recipient matches; for one vector
per flavour it also runs an `age` encrypt/decrypt round-trip. If
`age` is not in PATH, `make verify` fails loudly; ordinary
`make test` skips cross-validation with a warning.

## License

BSD-3-Clause. See [LICENSE](./LICENSE).
