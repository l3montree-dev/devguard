//go:build ignore

// Run with: go run scripts/gen_admin_key.go
//
// Outputs a hex-encoded P-256 ECDSA key pair.
// Save the public key output to a file and point INSTANCE_ADMIN_PUB_KEY_PATH at it.
// Keep the private key – use it to sign requests via services.SignRequest.

package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate key: %v\n", err)
		os.Exit(1)
	}

	privHex := hex.EncodeToString(priv.Bytes())

	// Uncompressed public key: 0x04 || X[32] || Y[32]
	pubBytes := priv.PublicKey().Bytes()
	pubHex := hex.EncodeToString(pubBytes[1:33]) + hex.EncodeToString(pubBytes[33:])

	fmt.Println("Private key (keep secret, use for signing):")
	fmt.Println(privHex)
	fmt.Println()
	fmt.Println("Public key (write to file, set INSTANCE_ADMIN_PUB_KEY_PATH):")
	fmt.Println(pubHex)
}
