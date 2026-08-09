package jobs

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/supaapps/platform93/internal/httpapi"
	"github.com/supaapps/platform93/internal/jobqueue"
	"github.com/supaapps/platform93/internal/outbound"
	"github.com/supaapps/platform93/internal/platform"
)

var (
	outboxDispatched = promauto.NewCounter(prometheus.CounterOpts{Name: "platform93_outbox_dispatched_total", Help: "Transactional outbox records dispatched."})
	deliveryAttempts = promauto.NewCounterVec(prometheus.CounterOpts{Name: "platform93_delivery_attempts_total", Help: "Asynchronous delivery attempts by type and result."}, []string{"type", "result"})
)

type Runner struct {
	app        *platform.App
	instanceID string
	client     *http.Client
}

func New(app *platform.App) *Runner {
	return &Runner{app: app, instanceID: uuid.NewString(), client: outbound.NewSafeHTTPClient(15 * time.Second)}
}

func (r *Runner) RunDispatcher(ctx context.Context) error {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	consecutiveFailures := 0
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			var dispatchErr error
			for range 100 {
				var dispatched bool
				dispatched, dispatchErr = r.dispatchOne(ctx)
				if dispatchErr != nil || !dispatched {
					break
				}
			}
			if dispatchErr != nil && ctx.Err() == nil {
				consecutiveFailures++
				delay := time.Duration(min(consecutiveFailures, 10)) * time.Second
				slog.Error("outbox dispatch failed", "error", dispatchErr, "retry_in", delay)
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(delay):
				}
			} else {
				consecutiveFailures = 0
			}
		}
	}
}
func (r *Runner) RunWorker(ctx context.Context) error {
	workers := river.NewWorkers()
	river.AddWorker(workers, &deliverySweepWorker{runner: r})
	river.AddWorker(workers, &billingReconciliationWorker{runner: r})
	river.AddWorker(workers, &storageSweepWorker{runner: r})
	client, err := river.NewClient(riverpgxv5.New(r.app.DB), &river.Config{
		ID:              r.instanceID,
		Workers:         workers,
		Queues:          map[string]river.QueueConfig{river.QueueDefault: {MaxWorkers: 10}},
		MaxAttempts:     10,
		JobTimeout:      2 * time.Minute,
		SoftStopTimeout: 30 * time.Second,
		PeriodicJobs: []*river.PeriodicJob{
			river.NewPeriodicJob(river.PeriodicInterval(time.Second), func() (river.JobArgs, *river.InsertOpts) {
				return deliverySweepArgs{}, nil
			}, &river.PeriodicJobOpts{ID: "platform93-delivery-sweep", RunOnStart: true}),
			river.NewPeriodicJob(river.PeriodicInterval(30*time.Second), func() (river.JobArgs, *river.InsertOpts) {
				return storageSweepArgs{}, nil
			}, &river.PeriodicJobOpts{ID: "platform93-storage-sweep", RunOnStart: true}),
		},
	})
	if err != nil {
		return err
	}
	if err = client.Start(ctx); err != nil {
		return err
	}
	<-client.Stopped()
	return nil
}

type billingReconciliationWorker struct {
	river.WorkerDefaults[jobqueue.BillingReconciliationArgs]
	runner *Runner
}

func (w *billingReconciliationWorker) Work(ctx context.Context, job *river.Job[jobqueue.BillingReconciliationArgs]) error {
	return httpapi.RunBillingReconciliation(ctx, w.runner.app, job.Args.RunID)
}

type deliverySweepArgs struct{}

func (deliverySweepArgs) Kind() string { return "platform93_delivery_sweep" }

type storageSweepArgs struct{}

func (storageSweepArgs) Kind() string { return "platform93_storage_sweep" }

type storageSweepWorker struct {
	river.WorkerDefaults[storageSweepArgs]
	runner *Runner
}

func (w *storageSweepWorker) Work(ctx context.Context, _ *river.Job[storageSweepArgs]) error {
	return httpapi.RunStorageSweep(ctx, w.runner.app)
}

type deliverySweepWorker struct {
	river.WorkerDefaults[deliverySweepArgs]
	runner *Runner
}

func (w *deliverySweepWorker) Work(ctx context.Context, _ *river.Job[deliverySweepArgs]) error {
	for range 25 {
		delivered, err := w.runner.deliverWebhook(ctx)
		if err != nil {
			return err
		}
		if !delivered {
			break
		}
	}
	for range 25 {
		delivered, err := w.runner.deliverNotification(ctx)
		if err != nil {
			return err
		}
		if !delivered {
			break
		}
	}
	return nil
}

func (r *Runner) dispatchOne(ctx context.Context) (bool, error) {
	tx, err := r.app.DB.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var outboxID, eventID, eventType string
	var applicationID *string
	err = tx.QueryRow(ctx, `SELECT o.id,e.id,e.application_id,e.event_type FROM outbox o JOIN domain_events e ON e.id=o.event_id WHERE o.dispatched_at IS NULL AND o.available_at<=now() ORDER BY o.available_at,o.id FOR UPDATE OF o SKIP LOCKED LIMIT 1`).Scan(&outboxID, &eventID, &applicationID, &eventType)
	if err == pgx.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if applicationID != nil {
		rows, queryErr := tx.Query(ctx, `SELECT id FROM webhook_endpoints WHERE application_id=$1 AND disabled_at IS NULL AND (cardinality(event_filters)=0 OR $2=ANY(event_filters))`, *applicationID, eventType)
		if queryErr != nil {
			return false, queryErr
		}
		endpointIDs := []string{}
		for rows.Next() {
			var endpointID string
			if rows.Scan(&endpointID) == nil {
				endpointIDs = append(endpointIDs, endpointID)
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return false, err
		}
		for _, endpointID := range endpointIDs {
			_, err = tx.Exec(ctx, `INSERT INTO webhook_deliveries (id,application_id,webhook_endpoint_id,event_id) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`, uuid.New(), *applicationID, endpointID, eventID)
			if err != nil {
				return false, err
			}
		}
	}
	_, err = tx.Exec(ctx, "UPDATE outbox SET dispatched_at=now(),locked_at=NULL,locked_by=NULL WHERE id=$1", outboxID)
	if err != nil {
		return false, err
	}
	if err = tx.Commit(ctx); err != nil {
		return true, err
	}
	outboxDispatched.Inc()
	return true, nil
}

func (r *Runner) deliverWebhook(ctx context.Context) (bool, error) {
	tx, err := r.app.DB.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var deliveryID, endpointID, uri, secretCipher, eventID, eventType, schemaVersion, contractSource, applicationID, occurred string
	var subject, correlationID, causationID *string
	var actor, data []byte
	err = tx.QueryRow(ctx, `SELECT d.id,w.id,w.uri,w.secret_ciphertext,e.id,e.event_type,e.schema_version,e.contract_source,e.application_id,e.occurred_at,e.subject,e.actor,e.correlation_id,e.causation_id,e.data
FROM webhook_deliveries d JOIN webhook_endpoints w ON w.id=d.webhook_endpoint_id JOIN domain_events e ON e.id=d.event_id
WHERE d.status IN ('pending','failed') AND d.next_attempt_at<=now() AND d.attempt_count<10
ORDER BY d.next_attempt_at,d.id FOR UPDATE OF d SKIP LOCKED LIMIT 1`).Scan(&deliveryID, &endpointID, &uri, &secretCipher, &eventID, &eventType, &schemaVersion, &contractSource, &applicationID, &occurred, &subject, &actor, &correlationID, &causationID, &data)
	if err == pgx.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := outbound.ValidateHTTPS(ctx, uri); err != nil {
		deliveryAttempts.WithLabelValues("webhook", "rejected").Inc()
		return true, r.failDelivery(ctx, tx, deliveryID, "destination is not allowed")
	}
	secret, err := r.app.Vault.Decrypt(secretCipher, "webhook-endpoint:"+endpointID)
	if err != nil {
		return true, r.failDelivery(ctx, tx, deliveryID, "webhook secret is unavailable")
	}
	payload := webhookEventPayload(eventID, applicationID, eventType, schemaVersion, contractSource, occurred, subject, actor, correlationID, causationID, data)
	timestamp := time.Now().Unix()
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(fmt.Sprintf("%d.", timestamp)))
	_, _ = mac.Write(payload)
	signature := fmt.Sprintf("t=%d,v1=%s", timestamp, hex.EncodeToString(mac.Sum(nil)))
	request, _ := http.NewRequestWithContext(ctx, "POST", uri, bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/cloudevents+json")
	request.Header.Set("Platform93-Signature", signature)
	response, err := r.client.Do(request)
	if err != nil {
		deliveryAttempts.WithLabelValues("webhook", "failed").Inc()
		return true, r.failDelivery(ctx, tx, deliveryID, "delivery request failed")
	}
	defer response.Body.Close()
	excerpt, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		deliveryAttempts.WithLabelValues("webhook", "failed").Inc()
		return true, r.failDelivery(ctx, tx, deliveryID, fmt.Sprintf("HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(excerpt))))
	}
	_, err = tx.Exec(ctx, `UPDATE webhook_deliveries SET status='delivered',attempt_count=attempt_count+1,response_status=$1,response_excerpt=$2,delivered_at=now() WHERE id=$3`, response.StatusCode, string(excerpt), deliveryID)
	if err != nil {
		return true, err
	}
	if err = tx.Commit(ctx); err != nil {
		return true, err
	}
	deliveryAttempts.WithLabelValues("webhook", "delivered").Inc()
	return true, nil
}

func webhookEventPayload(eventID, applicationID, eventType, schemaVersion, contractSource, occurred string, subject *string, actor []byte, correlationID, causationID *string, data []byte) []byte {
	payload, _ := json.Marshal(map[string]any{
		"specversion": "1.0", "id": eventID, "source": "platform93://applications/" + applicationID,
		"type": eventType, "contract_source": contractSource, "time": occurred, "subject": subject, "application_id": applicationID,
		"schema_version": schemaVersion, "actor": json.RawMessage(actor), "correlation_id": correlationID,
		"causation_id": causationID, "data": json.RawMessage(data),
	})
	return payload
}
func (r *Runner) failDelivery(ctx context.Context, tx pgx.Tx, id, message string) error {
	_, err := tx.Exec(ctx, `UPDATE webhook_deliveries SET status=CASE WHEN attempt_count>=9 THEN 'dead' ELSE 'failed' END,attempt_count=attempt_count+1,next_attempt_at=now()+(interval '1 second'*power(2,least(attempt_count,10))),response_excerpt=$1 WHERE id=$2`, message, id)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
