package authorization

import "testing"

func TestValidateRelativePermission(t *testing.T) {
	valid := []string{"*", "invoices:read", "members:42:read", "members:42:*", "feature_name:read-only"}
	for _, value := range valid {
		if err := ValidateRelativePermission(value); err != nil {
			t.Errorf("valid permission %q rejected: %v", value, err)
		}
	}
	invalid := []string{"", "read write", "read\twrite", "read\nwrite", "read\u200bwrite", "read%20write", "read/write", `read\write`, ":read", "read:", "read::write", ".:read", "..:read", "read:*:write", "read*"}
	for _, value := range invalid {
		if err := ValidateRelativePermission(value); err == nil {
			t.Errorf("invalid permission %q accepted", value)
		}
	}
}

func FuzzValidateRelativePermission(f *testing.F) {
	for _, seed := range []string{"invoices:read", "members:42:*", "read write", "read\u200bwrite", "../read"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		err := ValidateRelativePermission(value)
		if err == nil {
			applicationID := "01900000-0000-7000-8000-000000000001"
			scope, canonicalErr := CanonicalScope(applicationID, nil, value)
			if canonicalErr != nil || ValidateScopeClaim(scope, applicationID) != nil {
				t.Fatalf("accepted permission did not produce a valid canonical scope: %q", value)
			}
		}
	})
}

func TestCanonicalScopeAndMatch(t *testing.T) {
	workspaceID := "01900000-0000-7000-8000-000000000002"
	scope, err := CanonicalScope("01900000-0000-7000-8000-000000000001", &workspaceID, "members:42:*")
	if err != nil {
		t.Fatal(err)
	}
	expected := "/applications/01900000-0000-7000-8000-000000000001/workspaces/01900000-0000-7000-8000-000000000002/members/42/*"
	if scope != expected || !Match(scope, expected[:len(expected)-1]+"read") {
		t.Fatalf("unexpected canonical scope or match: %q", scope)
	}
	if Match(scope, "/applications/01900000-0000-7000-8000-000000000001/workspaces/other/members/42/read") {
		t.Fatal("wildcard crossed a complete path boundary")
	}
}

func TestValidateScopeClaimRejectsWhitespaceInjection(t *testing.T) {
	applicationID := "01900000-0000-7000-8000-000000000001"
	valid := "/applications/" + applicationID + "/members/42/read"
	if err := ValidateScopeClaim(valid, applicationID); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{valid + "  " + valid, valid + "\t" + valid, valid + "\n" + valid, "/applications/other/members/42/read"} {
		if err := ValidateScopeClaim(value, applicationID); err == nil {
			t.Errorf("invalid claim %q accepted", value)
		}
	}
}
