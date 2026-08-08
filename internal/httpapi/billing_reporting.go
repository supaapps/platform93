package httpapi

import (
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/supaapps/platform93/internal/kernel"
)

func (s *Server) getInvoice(w http.ResponseWriter, r *http.Request) {
	s.writeBillingResource(w, r, "invoices", "invoice_id")
}
func (s *Server) getPayment(w http.ResponseWriter, r *http.Request) {
	s.writeBillingResource(w, r, "payments", "payment_id")
}
func (s *Server) getRefund(w http.ResponseWriter, r *http.Request) {
	s.writeBillingResource(w, r, "refunds", "refund_id")
}
func (s *Server) getDispute(w http.ResponseWriter, r *http.Request) {
	s.writeBillingResource(w, r, "disputes", "dispute_id")
}

func (s *Server) writeBillingResource(w http.ResponseWriter, r *http.Request, table, parameter string) {
	allowed := map[string]bool{"invoices": true, "payments": true, "refunds": true, "disputes": true}
	if !allowed[table] {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "invalid_resource", "The billing resource is invalid.")
		return
	}
	var value []byte
	err := s.app.DB.QueryRow(r.Context(), fmt.Sprintf(`SELECT to_jsonb(resource) FROM %s resource
WHERE resource.id=$1 AND resource.application_id=$2`, table), chi.URLParam(r, parameter), chi.URLParam(r, "application_id")).Scan(&value)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "billing_resource_not_found", "The billing resource was not found.")
		return
	}
	kernel.WriteJSON(w, http.StatusOK, decodeAny(value))
}

func (s *Server) billingStatistics(w http.ResponseWriter, r *http.Request) {
	now := s.app.Now().UTC()
	from, to := now.AddDate(0, 0, -30), now
	var err error
	if value := r.URL.Query().Get("from"); value != "" {
		from, err = time.Parse(time.RFC3339, value)
	}
	if err == nil {
		if value := r.URL.Query().Get("to"); value != "" {
			to, err = time.Parse(time.RFC3339, value)
		}
	}
	if err != nil || !from.Before(to) || to.Sub(from) > 366*24*time.Hour || to.After(now.Add(5*time.Minute)) {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_statistics_range", "The statistics range must be valid, no longer than 366 days, and not in the future.")
		return
	}
	applicationID := chi.URLParam(r, "application_id")
	revenue, err := s.currencyTotals(r, `SELECT currency,sum(amount_received_minor) FROM payments
WHERE application_id=$1 AND status='succeeded' AND created_at>=$2 AND created_at<$3 GROUP BY currency`, applicationID, from, to)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Billing statistics could not be loaded.")
		return
	}
	refunds, err := s.currencyTotals(r, `SELECT currency,sum(amount_minor) FROM refunds
WHERE application_id=$1 AND status='succeeded' AND created_at>=$2 AND created_at<$3 GROUP BY currency`, applicationID, from, to)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Billing statistics could not be loaded.")
		return
	}
	statusCounts := map[string]map[string]int64{}
	for _, resource := range []string{"subscriptions", "invoices", "payments", "refunds", "disputes"} {
		rows, queryErr := s.app.DB.Query(r.Context(), fmt.Sprintf(`SELECT status,count(*) FROM %s WHERE application_id=$1 GROUP BY status`, resource), applicationID)
		if queryErr != nil {
			kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Billing statistics could not be loaded.")
			return
		}
		counts := map[string]int64{}
		for rows.Next() {
			var status string
			var count int64
			if rows.Scan(&status, &count) == nil {
				counts[status] = count
			}
		}
		rows.Close()
		statusCounts[resource] = counts
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"from": from, "to": to, "revenue_minor_by_currency": revenue,
		"refunds_minor_by_currency": refunds, "status_counts": statusCounts})
}

func (s *Server) currencyTotals(r *http.Request, query string, arguments ...any) ([]map[string]any, error) {
	rows, err := s.app.DB.Query(r.Context(), query, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []map[string]any{}
	for rows.Next() {
		var currency string
		var amount int64
		if err = rows.Scan(&currency, &amount); err != nil {
			return nil, err
		}
		result = append(result, map[string]any{"currency": currency, "amount_minor": amount})
	}
	sort.Slice(result, func(i, j int) bool { return result[i]["currency"].(string) < result[j]["currency"].(string) })
	return result, rows.Err()
}
