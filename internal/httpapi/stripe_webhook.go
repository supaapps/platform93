package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/supaapps/platform93/internal/kernel"
)

var errStripeAssociation = errors.New("invalid or conflicting Stripe application association")
var errStripeMappingPending = errors.New("Stripe application mapping is not available yet")

const stripeApplicationQuery = `SELECT a.id FROM applications a JOIN provider_connections pc ON pc.id=$2
WHERE a.id=$1 AND a.deleted_at IS NULL AND pc.status='active' AND (pc.application_id=a.id OR
(pc.application_id IS NULL AND pc.organization_id=a.organization_id AND pc.inheritable) OR
(pc.application_id IS NULL AND pc.organization_id IS NULL AND pc.inheritable))`

type stripeEvent struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	APIVersion string `json:"api_version"`
	Data       struct {
		Object map[string]any `json:"object"`
	} `json:"data"`
}

type stripeAcknowledgement struct {
	Received bool   `json:"received"`
	Status   string `json:"status"`
	Reason   string `json:"reason,omitempty"`
}

// The same dispatch table decides support before routing and performs processing.
type stripeNormalizer func(*Server, context.Context, pgx.Tx, string, string, map[string]any) error

var stripeNormalizers = map[string]stripeNormalizer{
	"checkout.session.completed":               stripeCheckoutCompleted,
	"checkout.session.async_payment_succeeded": stripeCheckoutCompleted,
	"checkout.session.expired":                 (*Server).normalizeStripeCheckoutExpiredTx,
	"customer.subscription.created":            (*Server).normalizeStripeSubscriptionTx,
	"customer.subscription.updated":            (*Server).normalizeStripeSubscriptionTx,
	"customer.subscription.deleted":            (*Server).normalizeStripeSubscriptionTx,
	"invoice.created":                          (*Server).normalizeStripeInvoiceTx,
	"invoice.finalized":                        (*Server).normalizeStripeInvoiceTx,
	"invoice.paid":                             (*Server).normalizeStripeInvoiceTx,
	"invoice.payment_failed":                   (*Server).normalizeStripeInvoiceTx,
	"invoice.voided":                           (*Server).normalizeStripeInvoiceTx,
	"invoice.marked_uncollectible":             (*Server).normalizeStripeInvoiceTx,
	"payment_intent.created":                   (*Server).normalizeStripePaymentTx,
	"payment_intent.processing":                (*Server).normalizeStripePaymentTx,
	"payment_intent.succeeded":                 (*Server).normalizeStripePaymentTx,
	"payment_intent.payment_failed":            (*Server).normalizeStripePaymentTx,
	"payment_intent.canceled":                  (*Server).normalizeStripePaymentTx,
	"payment_intent.amount_capturable_updated": (*Server).normalizeStripePaymentTx,
	"refund.created":                           (*Server).normalizeStripeRefundTx,
	"refund.updated":                           (*Server).normalizeStripeRefundTx,
	"refund.failed":                            (*Server).normalizeStripeRefundTx,
	"charge.dispute.created":                   (*Server).normalizeStripeDisputeTx,
	"charge.dispute.updated":                   (*Server).normalizeStripeDisputeTx,
	"charge.dispute.closed":                    (*Server).normalizeStripeDisputeTx,
}

func stripeCheckoutCompleted(s *Server, ctx context.Context, tx pgx.Tx, app, connection string, object map[string]any) error {
	return s.normalizeStripeCheckoutTx(ctx, tx, app, connection, object, true)
}
func (s *Server) normalizeStripeCheckoutExpiredTx(ctx context.Context, tx pgx.Tx, app, connection string, object map[string]any) error {
	return s.normalizeStripeCheckoutTx(ctx, tx, app, connection, object, false)
}

func (s *Server) stripeWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2<<20))
	if err != nil {
		kernel.WriteProblem(w, r, 400, "invalid_webhook_body", "The webhook body is invalid.")
		return
	}
	var connectionID string
	var webhookCipher *string
	err = s.app.DB.QueryRow(r.Context(), `SELECT pc.id,pc.webhook_secret_ciphertext FROM provider_connections pc
LEFT JOIN applications a ON a.id=pc.application_id WHERE pc.public_id=$1 AND pc.provider='stripe' AND pc.status='active'
AND (pc.application_id IS NULL OR a.deleted_at IS NULL)`, chi.URLParam(r, "connection_public_id")).Scan(&connectionID, &webhookCipher)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (webhookCipher == nil || *webhookCipher == "") {
		kernel.WriteProblem(w, r, 404, "provider_connection_not_found", "The provider connection was not found.")
		return
	}
	if err != nil {
		kernel.WriteProblem(w, r, 500, "provider_connection_unavailable", "The provider connection could not be loaded.")
		return
	}
	secret, err := s.app.Vault.Decrypt(*webhookCipher, "billing-provider:"+connectionID+":webhook")
	if err != nil {
		kernel.WriteProblem(w, r, 500, "provider_connection_unavailable", "The provider signing configuration is unavailable.")
		return
	}
	if !verifyStripeSignature(r.Header.Get("Stripe-Signature"), body, string(secret), s.app.Now()) {
		kernel.WriteProblem(w, r, 400, "invalid_webhook_signature", "The Stripe webhook signature is invalid.")
		return
	}
	var event stripeEvent
	if json.Unmarshal(body, &event) != nil || !validStripeEvent(event) {
		kernel.WriteProblem(w, r, 400, "invalid_webhook_event", "The Stripe event is invalid.")
		return
	}
	if stripeNormalizers[event.Type] == nil {
		s.ignoreStripeEvent(w, r, connectionID, event, "unsupported_event")
		return
	}
	if stringValue(event.Data.Object["id"]) == "" {
		kernel.WriteProblem(w, r, 400, "invalid_webhook_event", "The Stripe event object is missing its identifier.")
		return
	}
	applicationID, err := s.resolveStripeApplication(r.Context(), connectionID, event.Type, event.Data.Object)
	if errors.Is(err, errStripeAssociation) {
		kernel.WriteProblem(w, r, 422, "provider_event_application_unavailable", "The Stripe event does not identify an application allowed to use this connection.")
		return
	}
	if errors.Is(err, errStripeMappingPending) {
		kernel.WriteProblem(w, r, 503, "provider_event_mapping_pending", "The Stripe event references Platform93 records whose mapping is not available yet.")
		return
	}
	if err != nil {
		kernel.WriteProblem(w, r, 500, "provider_event_routing_failed", "The Stripe event association could not be loaded.")
		return
	}
	if applicationID == "" {
		s.ignoreStripeEvent(w, r, connectionID, event, "unrelated_event")
		return
	}
	cipher, err := s.app.Vault.Encrypt(body, "provider-event:"+connectionID+":"+event.ID)
	if err != nil {
		kernel.WriteProblem(w, r, 500, "webhook_storage_failed", "The webhook event could not be stored.")
		return
	}
	_, err = s.app.DB.Exec(r.Context(), `INSERT INTO provider_events(id,application_id,provider_connection_id,provider_event_id,api_version,event_type,raw_body_ciphertext)
VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(provider_connection_id,provider_event_id) DO NOTHING`, kernel.NewID(), applicationID, connectionID, event.ID, event.APIVersion, event.Type, cipher)
	if err != nil {
		kernel.WriteProblem(w, r, 500, "webhook_storage_failed", "The webhook event could not be stored.")
		return
	}
	status, err := s.processStripeReceipt(r.Context(), connectionID, event.ID, applicationID, event.Type)
	if errors.Is(err, errStripeMappingPending) {
		kernel.WriteProblem(w, r, 503, "provider_event_mapping_pending", "The Stripe event references Platform93 records whose mapping is not available yet.")
		return
	}
	if errors.Is(err, errStripeAssociation) {
		kernel.WriteProblem(w, r, 422, "provider_event_application_unavailable", "The event conflicts with its stored provider receipt.")
		return
	}
	if err != nil {
		kernel.WriteProblem(w, r, 500, "webhook_processing_failed", "The webhook was stored but processing failed.")
		return
	}
	kernel.WriteJSON(w, 200, stripeAcknowledgement{Received: true, Status: status})
}

func validStripeEvent(event stripeEvent) bool {
	if event.ID == "" || len(event.ID) > 255 || event.Type == "" || len(event.Type) > 255 || event.Data.Object == nil {
		return false
	}
	for _, value := range []string{event.ID, event.Type} {
		for _, c := range value {
			if c < 33 || c > 126 {
				return false
			}
		}
	}
	return true
}

func (s *Server) ignoreStripeEvent(w http.ResponseWriter, r *http.Request, connection string, event stripeEvent, reason string) {
	slog.Info("stripe_webhook_ignored", "connection_id", connection, "event_id", event.ID, "event_type", event.Type, "reason", reason, "request_id", kernel.RequestID(r.Context()))
	kernel.WriteJSON(w, 200, stripeAcknowledgement{Received: true, Status: "ignored", Reason: reason})
}

// No pool queries or nested transactions may run while this callback holds a receipt lock.
func (s *Server) withStripeTransaction(ctx context.Context, run func(pgx.Tx) error) error {
	tx, err := s.app.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = run(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Table/column names are internal constants; identifiers are still quoted.
func stripeRelatedID(ctx context.Context, tx pgx.Tx, application, connection, table, column, value string) (*string, error) {
	if value == "" {
		return nil, nil
	}
	var id, owner string
	err := tx.QueryRow(ctx, `SELECT id,application_id FROM `+pgx.Identifier{table}.Sanitize()+` WHERE provider_connection_id=$1 AND `+pgx.Identifier{column}.Sanitize()+`=$2`, connection, value).Scan(&id, &owner)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if owner != application {
		return nil, errStripeAssociation
	}
	return &id, nil
}

func (s *Server) processStripeReceipt(ctx context.Context, connection, eventID, application, expectedType string) (string, error) {
	status := "processed"
	err := s.withStripeTransaction(ctx, func(tx pgx.Tx) error {
		var id, owner, eventType, cipher, current string
		if err := tx.QueryRow(ctx, `SELECT id,application_id,event_type,raw_body_ciphertext,status FROM provider_events
WHERE provider_connection_id=$1 AND provider_event_id=$2 FOR UPDATE`, connection, eventID).Scan(&id, &owner, &eventType, &cipher, &current); err != nil {
			return err
		}
		if owner != application || eventType != expectedType {
			return errStripeAssociation
		}
		if current == "processed" || current == "ignored" {
			status = "duplicate"
			return nil
		}
		var allowed string
		if err := tx.QueryRow(ctx, stripeApplicationQuery+` FOR SHARE OF a,pc`, application, connection).Scan(&allowed); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errStripeAssociation
			}
			return err
		}
		body, err := s.app.Vault.Decrypt(cipher, "provider-event:"+connection+":"+eventID)
		if err != nil {
			return err
		}
		var event stripeEvent
		if json.Unmarshal(body, &event) != nil || !validStripeEvent(event) || event.ID != eventID || event.Type != eventType {
			return fmt.Errorf("stored Stripe event is invalid")
		}
		if normalize := stripeNormalizers[eventType]; normalize != nil {
			if err = normalize(s, ctx, tx, application, connection, event.Data.Object); err != nil {
				return err
			}
		} else {
			status = "ignored"
		}
		_, err = tx.Exec(ctx, `UPDATE provider_events SET status=$1,attempts=attempts+1,last_error=NULL,processed_at=now() WHERE id=$2`, status, id)
		return err
	})
	if err != nil {
		// Do not overwrite another retry's completed result after releasing the lock.
		failureCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_, _ = s.app.DB.Exec(failureCtx, `UPDATE provider_events SET status='failed',attempts=attempts+1,last_error='Stripe processing failed; retry delivery or replay.'
WHERE provider_connection_id=$1 AND provider_event_id=$2 AND application_id=$3 AND event_type=$4 AND status NOT IN ('processed','ignored')`, connection, eventID, application, expectedType)
	}
	return status, err
}

type stripeLinkage struct {
	applications, checkouts map[string]bool
	marked                  bool
}

func collectStripeLinkage(object map[string]any) (stripeLinkage, error) {
	result := stripeLinkage{applications: map[string]bool{}, checkouts: map[string]bool{}}
	var visit func(map[string]any, int) error
	visit = func(current map[string]any, depth int) error {
		if depth > 6 {
			return errStripeAssociation
		}
		if metadata, ok := current["metadata"].(map[string]any); ok {
			for key, value := range metadata {
				if !strings.HasPrefix(key, "platform93_") {
					continue
				}
				result.marked = true
				switch key {
				case "platform93_application_id", "platform93_checkout_id", "platform93_product_id", "platform93_price_id", "platform93_subject_id":
					text, ok := value.(string)
					if !ok {
						return errStripeAssociation
					}
					id, err := uuid.Parse(text)
					if err != nil || id == uuid.Nil || !strings.EqualFold(id.String(), text) {
						return errStripeAssociation
					}
					if key == "platform93_application_id" {
						result.applications[id.String()] = true
					}
					if key == "platform93_checkout_id" {
						result.checkouts[id.String()] = true
					}
				}
			}
		}
		for _, key := range []string{"parent", "subscription_details", "payment_intent", "invoice", "subscription", "customer", "charge"} {
			if nested, ok := current[key].(map[string]any); ok {
				if err := visit(nested, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	err := visit(object, 0)
	return result, err
}

func (s *Server) resolveStripeApplication(ctx context.Context, connection, eventType string, object map[string]any) (string, error) {
	linkage, err := collectStripeLinkage(object)
	if err != nil {
		return "", err
	}
	apps, err := s.stripeEventApplicationsFromRecords(ctx, connection, eventType, object)
	if err != nil {
		return "", err
	}
	for _, app := range apps {
		linkage.applications[app] = true
	}
	for checkout := range linkage.checkouts {
		var app, ownerConnection string
		err = s.app.DB.QueryRow(ctx, `SELECT application_id,provider_connection_id FROM checkout_sessions WHERE id=$1`, checkout).Scan(&app, &ownerConnection)
		if errors.Is(err, pgx.ErrNoRows) {
			return "", errStripeMappingPending
		}
		if err != nil {
			return "", err
		}
		if ownerConnection != connection {
			return "", errStripeAssociation
		}
		linkage.applications[app] = true
	}
	if len(linkage.applications) > 1 {
		return "", errStripeAssociation
	}
	if len(linkage.applications) == 0 {
		if linkage.marked {
			return "", errStripeMappingPending
		}
		return "", nil
	}
	var application string
	for app := range linkage.applications {
		application = app
	}
	var allowed string
	err = s.app.DB.QueryRow(ctx, stripeApplicationQuery, application, connection).Scan(&allowed)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errStripeAssociation
	}
	if err != nil {
		return "", err
	}
	return application, nil
}
