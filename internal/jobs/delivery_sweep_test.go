package jobs

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestDeliverySweepsRunBothChannelsAndPreserveErrors(t *testing.T) {
	notificationError, webhookError := errors.New("notification failure"), errors.New("webhook failure")
	for _, test := range []struct {
		name                  string
		notification, webhook error
	}{
		{"healthy", nil, nil},
		{"notification failure", notificationError, nil},
		{"webhook failure", nil, webhookError},
		{"both fail", notificationError, webhookError},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls []string
			err := runDeliverySweeps(context.Background(), func(context.Context) (bool, error) {
				calls = append(calls, "notification")
				return false, test.notification
			}, func(context.Context) (bool, error) {
				calls = append(calls, "webhook")
				return false, test.webhook
			})
			if !reflect.DeepEqual(calls, []string{"notification", "webhook"}) {
				t.Fatalf("unexpected delivery order: %v", calls)
			}
			for _, expected := range []error{test.notification, test.webhook} {
				if expected != nil && !errors.Is(err, expected) {
					t.Fatalf("missing retryable error %v: %v", expected, err)
				}
			}
			if test.notification == nil && test.webhook == nil && err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDeliverySweepsBoundEachChannel(t *testing.T) {
	var notifications, webhooks int
	err := runDeliverySweeps(context.Background(), func(context.Context) (bool, error) {
		notifications++
		return true, nil
	}, func(context.Context) (bool, error) {
		webhooks++
		return true, nil
	})
	if err != nil || notifications != 25 || webhooks != 25 {
		t.Fatalf("unexpected sweep counts: notifications=%d webhooks=%d err=%v", notifications, webhooks, err)
	}
}
