package authorization

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestScopeIntersection(t *testing.T) {
	const prefix = "/applications/01900000-0000-7000-8000-000000000001/"
	for _, tc := range []struct {
		name              string
		left, right, want []string
	}{
		{"exact", []string{prefix + "documents/read"}, []string{prefix + "documents/read"}, []string{prefix + "documents/read"}},
		{"broad live", []string{prefix + "*"}, []string{prefix + "documents/read"}, []string{prefix + "documents/read"}},
		{"broad credential", []string{prefix + "documents/read"}, []string{prefix + "*"}, []string{prefix + "documents/read"}},
		{"nested wildcard", []string{prefix + "*"}, []string{prefix + "documents/*"}, []string{prefix + "documents/*"}},
		{"boundary", []string{prefix + "doc/*"}, []string{prefix + "documents/read"}, []string{}},
		{"empty credential", []string{prefix + "*"}, nil, []string{}},
		{"empty live", nil, []string{prefix + "*"}, []string{}},
		{"malformed", []string{prefix + "documents/read write"}, []string{prefix + "*"}, []string{}},
		{"protocol is not permission", []string{"openid"}, []string{"openid"}, []string{}},
		{"deduplicate sort", []string{prefix + "*", prefix + "documents/read"}, []string{prefix + "documents/write", prefix + "documents/read", prefix + "documents/read"}, []string{prefix + "documents/read", prefix + "documents/write"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Intersect(tc.left, tc.right); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
			if got := Intersect(tc.right, tc.left); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("not commutative: %v", got)
			}
		})
	}
}

func FuzzScopeIntersectionCannotExpand(f *testing.F) {
	f.Add("/applications/example/*", "/applications/example/documents/read")
	f.Add("/applications/example/doc/*", "/applications/example/documents/read")
	f.Add("", "/applications/example/*")
	f.Fuzz(func(t *testing.T, a, b string) {
		if len(a)+len(b) > 4096 {
			t.Skip()
		}
		left, right := strings.Split(a, "|"), strings.Split(b, "|")
		got := Intersect(left, right)
		if !sort.StringsAreSorted(got) {
			t.Fatal("unsorted result")
		}
		covered := func(values []string, wanted string) bool {
			for _, scope := range values {
				if Match(scope, wanted) {
					return true
				}
			}
			return false
		}
		for i, scope := range got {
			if !covered(left, scope) || !covered(right, scope) {
				t.Fatal("intersection expanded authority")
			}
			if i > 0 && got[i-1] == scope {
				t.Fatal("duplicate scope")
			}
		}
	})
}
