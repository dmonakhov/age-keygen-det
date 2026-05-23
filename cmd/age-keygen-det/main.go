// Command age-keygen-det derives deterministic age identities from
// a 32-byte uniform seed. See the package documentation in
// pkg/agekeygendet for the library API.
package main

import (
	"fmt"
	"os"
)

const version = "0.0.0"

func main() {
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "-version", "--version", "-v":
			fmt.Printf("age-keygen-det v%s (scaffold)\n", version)
			return
		}
	}
	fmt.Fprintf(os.Stderr, "age-keygen-det v%s (scaffold, derivation not yet wired)\n", version)
}
