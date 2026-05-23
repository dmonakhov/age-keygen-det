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
age-keygen-det -type classic -hex-file seed.txt -label "vault gen 0"
```

```
# label: vault gen 0
# public key: age19ljh...
AGE-SECRET-KEY-1QQQ...
```

The seed content is whitespace-tolerant: spaces, tabs, and
newlines are stripped before validating the result is exactly 64
hex characters.

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
