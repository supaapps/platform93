package httpapi

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/supaapps/platform93/internal/kernel"
)

var corsRequestHeaders = map[string]struct{}{
	"accept": {}, "authorization": {}, "content-type": {}, "idempotency-key": {}, "if-match": {},
}

func (s *Server) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		if origin == "" {
			next.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/oidc/.well-known/openid-configuration" || r.URL.Path == "/oidc/jwks.json" {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			if r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Accept")
				w.Header().Set("Access-Control-Max-Age", "600")
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		applicationID := applicationIDFromAPIPath(r.URL.Path)
		allowed := s.platformOriginAllowed(origin)
		if !allowed && applicationID != "" {
			allowed = s.applicationOriginAllowed(r.Context(), applicationID, origin)
		} else if !allowed && strings.HasPrefix(r.URL.Path, "/oidc/") {
			allowed = s.oauthOriginAllowed(r.Context(), origin)
		} else if applicationID == "" && !strings.HasPrefix(r.URL.Path, "/oidc/") {
			next.ServeHTTP(w, r)
			return
		}
		if !allowed {
			writeCORSProblem(w, r)
			return
		}
		if r.Method == http.MethodOptions && !validCORSPreflight(r) {
			writeCORSProblem(w, r)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Add("Vary", "Origin")
		w.Header().Set("Access-Control-Expose-Headers", "ETag, Retry-After, X-Request-ID")
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Accept, Authorization, Content-Type, Idempotency-Key, If-Match")
			w.Header().Set("Access-Control-Max-Age", "600")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) platformOriginAllowed(origin string) bool {
	requestOrigin, requestOK := normalizedWebOrigin(origin)
	publicOrigin, publicOK := normalizedWebOrigin(s.app.PublicURL)
	return requestOK && publicOK && requestOrigin == origin && requestOrigin == publicOrigin
}

func applicationIDFromAPIPath(path string) string {
	const prefix = "/v1/applications/"
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	remainder := strings.TrimPrefix(path, prefix)
	if index := strings.IndexByte(remainder, '/'); index >= 0 {
		return remainder[:index]
	}
	return remainder
}

func (s *Server) applicationOriginAllowed(ctx context.Context, applicationID, origin string) bool {
	if _, ok := normalizedWebOrigin(origin); !ok {
		return false
	}
	if s.clientRedirectOriginAllowed(ctx, applicationID, origin) {
		return true
	}
	var verified bool
	_ = s.app.DB.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM application_domains
WHERE application_id=$1 AND verified_at IS NOT NULL AND 'https://' || hostname=$2)`, applicationID, origin).Scan(&verified)
	return verified
}

func (s *Server) oauthOriginAllowed(ctx context.Context, origin string) bool {
	return s.clientRedirectOriginAllowed(ctx, "", origin)
}

func (s *Server) clientRedirectOriginAllowed(ctx context.Context, applicationID, origin string) bool {
	normalized, ok := normalizedWebOrigin(origin)
	if !ok || normalized != origin {
		return false
	}
	query := `SELECT redirect_uris,post_logout_redirect_uris FROM clients
WHERE disabled_at IS NULL AND client_type='public'`
	arguments := []any{}
	if applicationID != "" {
		query += " AND application_id=$1"
		arguments = append(arguments, applicationID)
	}
	rows, err := s.app.DB.Query(ctx, query, arguments...)
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var redirects, postLogoutRedirects []string
		if rows.Scan(&redirects, &postLogoutRedirects) != nil {
			return false
		}
		for _, candidate := range append(redirects, postLogoutRedirects...) {
			if candidateOrigin, valid := normalizedWebOrigin(candidate); valid && candidateOrigin == normalized {
				return true
			}
		}
	}
	return false
}

func normalizedWebOrigin(value string) (string, bool) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.User != nil || parsed.Host == "" || parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", false
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", false
	}
	host := strings.ToLower(parsed.Hostname())
	port := parsed.Port()
	if port != "" && !(parsed.Scheme == "http" && port == "80") && !(parsed.Scheme == "https" && port == "443") {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return parsed.Scheme + "://" + host, true
}

func validCORSPreflight(r *http.Request) bool {
	method := strings.ToUpper(strings.TrimSpace(r.Header.Get("Access-Control-Request-Method")))
	if method != http.MethodGet && method != http.MethodPost && method != http.MethodPut && method != http.MethodPatch && method != http.MethodDelete {
		return false
	}
	for _, header := range strings.Split(r.Header.Get("Access-Control-Request-Headers"), ",") {
		header = strings.ToLower(strings.TrimSpace(header))
		if header == "" {
			continue
		}
		if _, allowed := corsRequestHeaders[header]; !allowed {
			return false
		}
	}
	return true
}

func writeCORSProblem(w http.ResponseWriter, r *http.Request) {
	kernel.WriteProblem(w, r, http.StatusForbidden, "origin_not_allowed", "The request origin is not allowed.")
}
