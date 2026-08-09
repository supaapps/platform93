package secure

import (
	"bytes"
	"strings"
	"testing"
)

func TestVaultEncryptsWithBoundContext(t *testing.T) {
	vault, err := NewVault(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := vault.Encrypt([]byte("provider-secret"), "application/one")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := vault.Decrypt(sealed, "application/one")
	if err != nil || string(plain) != "provider-secret" {
		t.Fatalf("round trip failed: %v", err)
	}
	if _, err := vault.Decrypt(sealed, "application/two"); err == nil {
		t.Fatal("ciphertext decrypted under a different context")
	}
}

func TestRandomTokenPrefixAndEntropy(t *testing.T) {
	token, err := RandomToken("p93_pat_", 32)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(token, "p93_pat_") || len(token) < 50 {
		t.Fatalf("unexpected token %q", token)
	}
}
