package httpapi

import (
	"github.com/ory/fosite"
	"reflect"
	"testing"
)

func TestOAuthScopesReplaceRelativeAndRevokedPermissions(t *testing.T) {
	canonical := "/applications/01900000-0000-7000-8000-000000000093/workspaces/read"
	for _, effective := range [][]string{{canonical}, {}} {
		request := fosite.NewAccessRequest(nil)
		request.GrantScope("openid")
		request.GrantScope("workspaces/read")
		request.GrantScope("/applications/01900000-0000-7000-8000-000000000093/billing/write")
		replaceApplicationScopes(request, effective)
		wanted := append([]string{"openid"}, effective...)
		if !reflect.DeepEqual([]string(request.GetGrantedScopes()), wanted) {
			t.Fatalf("scope replacement: got %v, want %v", request.GetGrantedScopes(), wanted)
		}
	}
}
