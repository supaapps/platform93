package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type stripeHTTPError struct{ StatusCode int }

func (e stripeHTTPError) Error() string {
	return fmt.Sprintf("Stripe request failed with status %d", e.StatusCode)
}

func checkoutRequestKey(r *http.Request) string {
	if r.Header.Get("Idempotency-Key") == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(actor(r).Type + ":" + actor(r).ID + ":" + r.Header.Get("Idempotency-Key")))
	return hex.EncodeToString(sum[:])
}

func (s *Server) markRejectedCheckout(ctx context.Context, id string, cause error) {
	var rejected stripeHTTPError
	if errors.As(cause, &rejected) && rejected.StatusCode >= 400 && rejected.StatusCode < 500 && rejected.StatusCode != 408 && rejected.StatusCode != 409 && rejected.StatusCode != 429 {
		_, _ = s.app.DB.Exec(ctx, `UPDATE checkout_sessions SET status='failed',updated_at=now() WHERE id=$1 AND status='pending'`, id)
	}
}

func (s *Server) persistCheckoutRequest(ctx context.Context, app, subjectType, subject, id string, form url.Values) error {
	tx, err := s.app.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	var locked bool
	if err = tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))`, app+":"+subjectType+":"+subject).Scan(&locked); err != nil || !locked {
		return fmt.Errorf("billing operation in progress")
	}
	data, err := json.Marshal(form)
	if err != nil {
		return err
	}
	result, err := tx.Exec(ctx, `UPDATE checkout_sessions SET provider_request=$1,updated_at=now() WHERE id=$2 AND application_id=$3 AND status='pending'
AND NOT EXISTS(SELECT 1 FROM billing_subject_cancellations WHERE application_id=$3 AND subject_type=$4 AND subject_id=$5)`, data, id, app, subjectType, subject)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return fmt.Errorf("checkout no longer eligible")
	}
	return tx.Commit(ctx)
}

type checkoutAttempt struct {
	id, provider, external, sealed, version, mode, status string
	form                                                  []byte
	created                                               time.Time
	requestKey                                            *string
	requestHash                                           []byte
	uri, reference                                        *string
}

func (s *Server) recoverCheckoutAttempts(ctx context.Context, app, subjectType, subject, product, key string, hash []byte, all bool) (map[string]any, error) {
	rows, err := s.app.DB.Query(ctx, `SELECT c.id,c.provider_connection_id,COALESCE(c.provider_session_id,''),p.secret_ciphertext,p.api_version,pr.mode,c.status,c.provider_request,c.created_at,c.request_key,c.request_hash,c.checkout_uri,c.external_reference
FROM checkout_sessions c JOIN prices pr ON pr.id=c.price_id JOIN provider_connections p ON p.id=c.provider_connection_id
WHERE c.application_id=$1 AND c.subject_type=$2 AND c.subject_id=$3 AND pr.product_id=$4
AND (c.status IN('pending','open') OR c.status='completed' AND pr.mode='recurring' AND NOT EXISTS(SELECT 1 FROM subscriptions s WHERE s.application_id=c.application_id AND s.metadata->>'platform93_checkout_id'=c.id::text))
AND ($5 OR ($6<>'' AND c.request_key=$6)) ORDER BY c.created_at LIMIT 101`, app, subjectType, subject, product, all, key)
	if err != nil {
		return nil, err
	}
	var attempts []checkoutAttempt
	for rows.Next() {
		var a checkoutAttempt
		if err = rows.Scan(&a.id, &a.provider, &a.external, &a.sealed, &a.version, &a.mode, &a.status, &a.form, &a.created, &a.requestKey, &a.requestHash, &a.uri, &a.reference); err != nil {
			rows.Close()
			return nil, err
		}
		attempts = append(attempts, a)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if len(attempts) > 100 {
		return nil, fmt.Errorf("too many unresolved checkouts")
	}
	for _, a := range attempts {
		if a.status != "completed" && time.Since(a.created) < time.Minute && (key == "" || a.requestKey == nil || *a.requestKey != key) {
			continue
		}
		if a.requestKey != nil && *a.requestKey == key && !bytes.Equal(hash, a.requestHash) {
			return nil, fmt.Errorf("idempotency key payload changed")
		}
		current, err := s.resolveCheckoutAttempt(ctx, app, a)
		if err != nil {
			return nil, err
		}
		if current == nil {
			continue
		}
		if stringValue(current["status"]) == "open" && key != "" && a.requestKey != nil && *a.requestKey == key {
			var available bool
			err = s.app.DB.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM billing_subject_cancellations WHERE application_id=$1 AND subject_type=$2 AND subject_id=$3)
AND CASE WHEN $2='workspace' THEN EXISTS(SELECT 1 FROM workspaces WHERE application_id=$1 AND id=$3 AND deleted_at IS NULL) ELSE EXISTS(SELECT 1 FROM users WHERE application_id=$1 AND id=$3 AND status='active') END`, app, subjectType, subject).Scan(&available)
			if err != nil || !available {
				return nil, fmt.Errorf("billing subject unavailable")
			}
			return map[string]any{"id": a.id, "status": "open", "checkout_uri": stringValue(current["url"]), "provider_session_id": stringValue(current["id"]), "external_reference": a.reference}, nil
		}
	}
	return nil, nil
}

func (s *Server) resolveCheckoutAttempt(ctx context.Context, app string, a checkoutAttempt) (map[string]any, error) {
	if a.external == "" && len(a.form) == 0 {
		// No provider call is permitted without first atomically saving its form.
		if time.Since(a.created) > time.Minute {
			_, err := s.app.DB.Exec(ctx, `UPDATE checkout_sessions SET status='failed',updated_at=now() WHERE id=$1 AND status='pending' AND provider_request IS NULL`, a.id)
			return nil, err
		}
		return nil, nil
	}
	secret, err := s.app.Vault.Decrypt(a.sealed, "billing-provider:"+a.provider+":secret")
	if err != nil {
		return nil, err
	}
	var data []byte
	if a.external != "" {
		data, err = stripeRequest(ctx, "GET", "https://api.stripe.com/v1/checkout/sessions/"+url.PathEscape(a.external), string(secret), a.version, "", url.Values{"expand[]": {"subscription"}})
	} else {
		var form url.Values
		legacy := boolValue(decodeMap(a.form)["legacy_unknown"])
		if legacy {
			var customer string
			err = s.app.DB.QueryRow(ctx, `SELECT b.provider_customer_id FROM billing_customers b JOIN checkout_sessions c ON c.application_id=b.application_id AND c.subject_type=b.subject_type AND c.subject_id=b.subject_id AND c.provider_connection_id=b.provider_connection_id WHERE c.id=$1 AND c.application_id=$2`, a.id, app).Scan(&customer)
			if err != nil {
				return nil, err
			}
			form = url.Values{"customer": {customer}}
		} else if err = json.Unmarshal(a.form, &form); err != nil {
			return nil, err
		}
		if !legacy && time.Since(a.created) < 23*time.Hour {
			data, err = stripeRequest(ctx, "POST", "https://api.stripe.com/v1/checkout/sessions", string(secret), a.version, "platform93-checkout-"+app+"-"+a.id, form)
			if err != nil {
				s.markRejectedCheckout(ctx, a.id, err)
				return nil, err
			}
		} else {
			// Never replay creation after Stripe may have pruned its idempotency key.
			var found map[string]any
			_, err = reconcileStripeList(ctx, string(secret), a.version, "https://api.stripe.com/v1/checkout/sessions", url.Values{"customer": {form.Get("customer")}}, func(value map[string]any) error {
				if stringValue(value["client_reference_id"]) == a.id && metadataString(value, "platform93_application_id") == app {
					found = value
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			if found == nil {
				return nil, fmt.Errorf("provider outcome requires administrator reconciliation")
			}
			a.external = stringValue(found["id"])
			return s.resolveCheckoutAttempt(ctx, app, a)
		}
	}
	if err != nil {
		return nil, err
	}
	var current map[string]any
	if err = json.Unmarshal(data, &current); err != nil {
		return nil, err
	}
	if stringValue(current["id"]) == "" {
		return nil, fmt.Errorf("invalid checkout response")
	}
	switch stringValue(current["status"]) {
	case "complete":
		current["client_reference_id"] = a.id
		if err = s.normalizeStripeCheckout(ctx, app, a.provider, current, true); err != nil {
			return nil, err
		}
		if a.mode == "recurring" {
			sub := mapValue(current["subscription"])
			if len(sub) == 0 {
				id := stripeObjectID(current["subscription"])
				if id == "" {
					return nil, fmt.Errorf("completed subscription unavailable")
				}
				body, e := stripeRequest(ctx, "GET", "https://api.stripe.com/v1/subscriptions/"+url.PathEscape(id), string(secret), a.version, "", nil)
				if e != nil {
					return nil, e
				}
				if e = json.Unmarshal(body, &sub); e != nil {
					return nil, e
				}
			}
			if err = s.normalizeStripeSubscription(ctx, app, a.provider, sub); err != nil {
				return nil, err
			}
		}
	case "expired":
		current["client_reference_id"] = a.id
		err = s.normalizeStripeCheckout(ctx, app, a.provider, current, false)
	case "open":
		if stringValue(current["url"]) == "" {
			return nil, fmt.Errorf("checkout URL unavailable")
		}
		result, updateErr := s.app.DB.Exec(ctx, `UPDATE checkout_sessions SET provider_session_id=$1,checkout_uri=$2,status='open',updated_at=now() WHERE id=$3 AND application_id=$4 AND status IN('pending','open')`, stringValue(current["id"]), stringValue(current["url"]), a.id, app)
		err = updateErr
		if err == nil && result.RowsAffected() != 1 {
			err = fmt.Errorf("checkout settled concurrently")
		}
	default:
		return nil, fmt.Errorf("unknown checkout state")
	}
	return current, err
}
