package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

type Vault struct{ key []byte }

func NewVault(key []byte) (*Vault, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("vault key must contain 32 bytes")
	}
	return &Vault{key: append([]byte(nil), key...)}, nil
}

func (v *Vault) Encrypt(plaintext []byte, context string) (string, error) {
	block, err := aes.NewCipher(v.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, plaintext, []byte(context))
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (v *Vault) Decrypt(value, context string) ([]byte, error) {
	sealed, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(v.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, fmt.Errorf("invalid encrypted value")
	}
	return gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], []byte(context))
}

func (v *Vault) Digest(value string) []byte {
	mac := hmac.New(sha256.New, v.key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

func RandomToken(prefix string, bytes int) (string, error) {
	value := make([]byte, bytes)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(value), nil
}
