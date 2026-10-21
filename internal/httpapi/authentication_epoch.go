package httpapi

import (
	"context"
	"net/http"
)

type authenticationEpochKey struct{}

// Bind the generation observed while verifying credentials, before releasing
// proof locks. Fetching it after verification would reintroduce the reset race.
func withAuthenticationEpoch(r *http.Request, epoch int64) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), authenticationEpochKey{}, epoch))
}

func authenticationEpoch(r *http.Request) (int64, bool) {
	epoch, ok := r.Context().Value(authenticationEpochKey{}).(int64)
	return epoch, ok
}
