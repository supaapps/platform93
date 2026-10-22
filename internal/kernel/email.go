package kernel

import (
	"unicode"
	"unicode/utf8"
)

// ValidEmailSenderName permits display names, not additional email headers.
func ValidEmailSenderName(value string) bool {
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > 200 {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}
