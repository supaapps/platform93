package httpapi

import (
	"errors"
	"log/slog"
	"net/http"
	"slices"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/supaapps/platform93/internal/kernel"
)

func objectOrEmpty(value map[string]any) map[string]any {
	if value == nil {
		return map[string]any{}
	}
	return value
}

func stringsOrEmpty(value []string) []string {
	if value == nil {
		return []string{}
	}
	return value
}

func uniqueConstraint(err error, constraints ...string) bool {
	var pgError *pgconn.PgError
	return errors.As(err, &pgError) && pgError.Code == "23505" && slices.Contains(constraints, pgError.ConstraintName)
}

func writeCreationProblem(w http.ResponseWriter, r *http.Request, err error, conflictCode, conflictDetail, failureCode string, constraints ...string) {
	if uniqueConstraint(err, constraints...) {
		kernel.WriteProblem(w, r, http.StatusConflict, conflictCode, conflictDetail)
		return
	}
	sqlState := ""
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		sqlState = pgError.Code
	}
	// Raw database errors may contain secrets or caller-controlled values.
	slog.Error("resource creation failed", "request_id", kernel.RequestID(r.Context()), "code", failureCode, "sqlstate", sqlState)
	kernel.WriteProblem(w, r, http.StatusInternalServerError, failureCode, "The resource could not be created. Retry the request.")
}
