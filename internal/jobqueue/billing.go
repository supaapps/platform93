package jobqueue

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
)

type BillingReconciliationArgs struct {
	RunID string `json:"run_id" river:"unique"`
}

func (BillingReconciliationArgs) Kind() string { return "platform93_billing_reconciliation" }

func InsertBillingReconciliation(ctx context.Context, pool *pgxpool.Pool, tx pgx.Tx, runID string) error {
	client, err := river.NewClient(riverpgxv5.New(pool), &river.Config{})
	if err != nil {
		return err
	}
	_, err = client.InsertTx(ctx, tx, BillingReconciliationArgs{RunID: runID}, &river.InsertOpts{
		MaxAttempts: 8,
		UniqueOpts:  river.UniqueOpts{ByArgs: true},
	})
	return err
}
