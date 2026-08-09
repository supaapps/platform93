package identity

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // TOTP interoperability requires HMAC-SHA1 by default (RFC 6238).
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

func GenerateTOTPSecret() (string, error) {
	value := make([]byte, 20)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(value), nil
}

func VerifyTOTP(secret, code string, now time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
	for offset := int64(-1); offset <= 1; offset++ {
		wanted, err := totpAt(secret, now.Unix()/30+offset)
		if err == nil && subtle.ConstantTimeCompare([]byte(wanted), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

func totpAt(secret string, counter int64) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", err
	}
	message := make([]byte, 8)
	binary.BigEndian.PutUint64(message, uint64(counter))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(message)
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 0x0f
	value := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1_000_000), nil
}
