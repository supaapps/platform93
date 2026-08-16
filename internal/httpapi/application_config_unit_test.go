package httpapi

import "testing"

func TestValidCustomTokenClaimKeys(t *testing.T) {
	t.Parallel()
	if !validCustomTokenClaimKeys([]string{"plan", "account_tier", "profile.region"}) {
		t.Fatal("expected safe unique custom token claim keys to pass")
	}
	for _, values := range [][]string{{"duplicate", "duplicate"}, {"bad key"}, {""}} {
		if validCustomTokenClaimKeys(values) {
			t.Fatalf("expected invalid keys to fail: %#v", values)
		}
	}
	many := make([]string, 33)
	for index := range many {
		many[index] = string(rune('a'+index%26)) + string(rune('0'+index/26))
	}
	if validCustomTokenClaimKeys(many) {
		t.Fatal("expected more than 32 keys to fail")
	}
}
