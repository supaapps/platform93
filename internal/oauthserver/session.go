package oauthserver

import (
	"encoding/json"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
)

// Session carries both OAuth access-token and OpenID Connect ID-token claims.
// Keeping one serializable type lets Fosite safely restore a grant on any pod.
type Session struct {
	AccessClaims  *jwt.JWTClaims                 `json:"access_claims"`
	IDClaims      *jwt.IDTokenClaims             `json:"id_claims"`
	AccessHeaders *jwt.Headers                   `json:"access_headers"`
	IDHeaders     *jwt.Headers                   `json:"id_headers"`
	ExpiresAt     map[fosite.TokenType]time.Time `json:"expires_at"`
	Username      string                         `json:"username"`
	Subject       string                         `json:"subject"`
}

var _ oauth2.JWTSessionContainer = (*Session)(nil)
var _ openid.Session = (*Session)(nil)

func NewSession(subject, username, kid string, now time.Time) *Session {
	accessHeaders := jwt.NewHeaders()
	accessHeaders.Add("kid", kid)
	accessHeaders.Add("typ", "JWT")
	idHeaders := jwt.NewHeaders()
	idHeaders.Add("kid", kid)
	idHeaders.Add("typ", "JWT")
	return &Session{
		AccessClaims:  &jwt.JWTClaims{Subject: subject, NotBefore: now.Add(-5 * time.Second), Extra: map[string]any{}},
		IDClaims:      &jwt.IDTokenClaims{Subject: subject, RequestedAt: now, AuthTime: now, Extra: map[string]any{}},
		AccessHeaders: accessHeaders,
		IDHeaders:     idHeaders,
		ExpiresAt:     map[fosite.TokenType]time.Time{},
		Username:      username,
		Subject:       subject,
	}
}

func (s *Session) GetJWTClaims() jwt.JWTClaimsContainer {
	if s.AccessClaims == nil {
		s.AccessClaims = &jwt.JWTClaims{Extra: map[string]any{}}
	}
	return s.AccessClaims
}

func (s *Session) GetJWTHeader() *jwt.Headers {
	if s.AccessHeaders == nil {
		s.AccessHeaders = jwt.NewHeaders()
	}
	return s.AccessHeaders
}

func (s *Session) IDTokenClaims() *jwt.IDTokenClaims {
	if s.IDClaims == nil {
		s.IDClaims = &jwt.IDTokenClaims{Extra: map[string]any{}}
	}
	return s.IDClaims
}

func (s *Session) IDTokenHeaders() *jwt.Headers {
	if s.IDHeaders == nil {
		s.IDHeaders = jwt.NewHeaders()
	}
	return s.IDHeaders
}

func (s *Session) SetExpiresAt(kind fosite.TokenType, expiresAt time.Time) {
	if s.ExpiresAt == nil {
		s.ExpiresAt = map[fosite.TokenType]time.Time{}
	}
	s.ExpiresAt[kind] = expiresAt
}

func (s *Session) GetExpiresAt(kind fosite.TokenType) time.Time {
	if s == nil || s.ExpiresAt == nil {
		return time.Time{}
	}
	return s.ExpiresAt[kind]
}

func (s *Session) GetUsername() string { return s.Username }
func (s *Session) GetSubject() string  { return s.Subject }

func (s *Session) Clone() fosite.Session {
	if s == nil {
		return nil
	}
	encoded, _ := json.Marshal(s)
	clone := new(Session)
	_ = json.Unmarshal(encoded, clone)
	return clone
}

func (s *Session) GetExtraClaims() map[string]interface{} {
	if s == nil || s.AccessClaims == nil {
		return nil
	}
	return s.AccessClaims.ToMap()
}
