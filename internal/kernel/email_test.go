package kernel

import (
	"strings"
	"testing"
)

func TestEmailSenderNameValidation(t *testing.T) {
	for _, value := range []string{"", "Example Team", "  Example  ", "Bücher & Co", `Team "Support"`, strings.Repeat("é", 200)} {
		if !ValidEmailSenderName(value) {
			t.Errorf("valid display name rejected: %q", value)
		}
	}
	for _, value := range []string{"Team\r\nBcc: other@example.test", "\nTeam", "Team\x00", "Team\tName", "Team\u0085Name", strings.Repeat("a", 201), string([]byte{0xff})} {
		if ValidEmailSenderName(value) {
			t.Errorf("unsafe or oversized display name accepted: %q", value)
		}
	}
}
