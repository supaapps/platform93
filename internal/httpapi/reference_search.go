package httpapi

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/supaapps/platform93/internal/kernel"
)

// Search pagination is opt-in so existing list consumers retain their ordering.
func referenceSearch(w http.ResponseWriter, r *http.Request, query string, args []any, id string, fields ...string) (string, []any, int, bool) {
	params := r.URL.Query()
	if !params.Has("query") && !params.Has("limit") && !params.Has("cursor") {
		return query, args, 0, true
	}
	limit := 20
	if raw := params.Get("limit"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 100 {
			kernel.WriteProblem(w, r, 422, "invalid_limit", "Search limit must be between 1 and 100.")
			return "", nil, 0, false
		}
		limit = value
	}
	term := strings.TrimSpace(params.Get("query"))
	if parsed, err := uuid.Parse(term); err == nil {
		term = parsed.String()
	}
	if utf8.RuneCountInString(term) > 200 {
		kernel.WriteProblem(w, r, 422, "invalid_query", "Search text must not exceed 200 characters.")
		return "", nil, 0, false
	}
	args = append(args, term)
	n := len(args)
	conditions := []string{fmt.Sprintf("%s::text=$%d", id, n)}
	for _, field := range fields {
		conditions = append(conditions, fmt.Sprintf("strpos(lower(%s),lower($%d::text))>0", field, n))
	}
	query += fmt.Sprintf(" AND ($%d::text='' OR %s)", n, strings.Join(conditions, " OR "))
	if cursor := params.Get("cursor"); cursor != "" {
		parsed, err := uuid.Parse(cursor)
		if err != nil || parsed.String() != cursor {
			kernel.WriteProblem(w, r, 422, "invalid_cursor", "The search cursor is invalid.")
			return "", nil, 0, false
		}
		args = append(args, cursor)
		query += fmt.Sprintf(" AND %s>$%d::uuid", id, len(args))
	}
	args = append(args, limit+1)
	query += fmt.Sprintf(" ORDER BY %s LIMIT $%d", id, len(args))
	return query, args, limit, true
}

func referencePage[T any](items []T, limit int, id func(T) string) ([]T, any) {
	if limit > 0 && len(items) > limit {
		return items[:limit], id(items[limit-1])
	}
	return items, nil
}
