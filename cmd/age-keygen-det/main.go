// Command age-keygen-det derives deterministic age identities from
// a 32-byte uniform seed. See design-draft.md for the design and
// the pkg/agekeygendet package for the library API.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/dmonakhov/age-keygen-det/pkg/agekeygendet"
)

const version = "0.0.0"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("age-keygen-det", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, `age-keygen-det v%s - deterministic age identity from a 32-byte seed.

usage: age-keygen-det -type <pq|classic> [flags]

Flags:
  -type pq|classic         key flavour (required)
  -hex-file PATH           read 32-byte seed from FILE (whitespace stripped)
  -hex-fd N                read 32-byte seed from open file descriptor N
  -label TEXT              prefix output with a "# label: TEXT" comment
  -o, --output FILE        write to FILE (mode 0600) instead of stdout
  -version                 print version and exit

If neither -hex-file nor -hex-fd is given, the seed is read from
/dev/tty with no echo. The seed is NEVER accepted on the command
line.

Output mirrors stock age-keygen; recover the recipient with:
  age-keygen -y identity.txt
`, version)
	}

	var (
		typeFlag   string
		hexFile    string
		hexFD      int
		label      string
		outputPath string
		showVer    bool
	)
	fs.StringVar(&typeFlag, "type", "", "key type: pq or classic (required)")
	fs.StringVar(&hexFile, "hex-file", "", "read 32-byte seed from FILE")
	fs.IntVar(&hexFD, "hex-fd", -1, "read 32-byte seed from open file descriptor N")
	fs.StringVar(&label, "label", "", "add a `# label: TEXT` comment line")
	fs.StringVar(&outputPath, "output", "", "write to FILE instead of stdout (mode 0600)")
	fs.StringVar(&outputPath, "o", "", "short for --output")
	fs.BoolVar(&showVer, "version", false, "print version and exit")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	if showVer {
		fmt.Fprintf(stdout, "age-keygen-det v%s\n", version)
		return 0
	}

	if typeFlag == "" {
		fmt.Fprintln(stderr, "age-keygen-det: -type is required (pq or classic)")
		return 2
	}

	var keyType agekeygendet.KeyType
	switch typeFlag {
	case "pq":
		keyType = agekeygendet.KeyTypePQ
	case "classic":
		keyType = agekeygendet.KeyTypeClassic
	default:
		fmt.Fprintf(stderr, "age-keygen-det: invalid -type %q (want pq or classic)\n", typeFlag)
		return 2
	}

	seed, err := readSeedHex(hexFile, hexFD, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "age-keygen-det: %v\n", err)
		return 2
	}

	derived, err := agekeygendet.DeriveFromSeed(seed, keyType)
	if err != nil {
		fmt.Fprintf(stderr, "age-keygen-det: %v\n", err)
		return 1
	}

	out := formatIdentity(derived, label)
	return writeOutput(out, outputPath, stdout, stderr)
}

// formatIdentity produces the age-keygen-style identity file body:
//
//	# label: <text>          (only if label != "")
//	# public key: <RECIPIENT>
//	<IDENTITY>
//
// See design-draft sec 5.2.
func formatIdentity(d *agekeygendet.DerivedIdentity, label string) []byte {
	var buf bytes.Buffer
	if label != "" {
		fmt.Fprintf(&buf, "# label: %s\n", label)
	}
	fmt.Fprintf(&buf, "# public key: %s\n", d.Recipient)
	fmt.Fprintln(&buf, d.Identity)
	return buf.Bytes()
}

func writeOutput(data []byte, outputPath string, stdout, stderr io.Writer) int {
	if outputPath == "" {
		if _, err := stdout.Write(data); err != nil {
			fmt.Fprintf(stderr, "write: %v\n", err)
			return 1
		}
		return 0
	}
	if err := os.WriteFile(outputPath, data, 0o600); err != nil {
		fmt.Fprintf(stderr, "write %q: %v\n", outputPath, err)
		return 1
	}
	return 0
}
