package kernel

import "context"

type contextKey string

const (
	requestIDKey contextKey = "request_id"
	actorKey     contextKey = "actor"
)

type Actor struct {
	Type          string   `json:"type"`
	ID            string   `json:"id,omitempty"`
	ApplicationID string   `json:"application_id,omitempty"`
	SessionID     string   `json:"session_id,omitempty"`
	Permissions   []string `json:"permissions,omitempty"`
	DelegatedBy   string   `json:"delegated_by,omitempty"`
}

func WithRequestID(ctx context.Context, value string) context.Context {
	return context.WithValue(ctx, requestIDKey, value)
}

func RequestID(ctx context.Context) string {
	value, _ := ctx.Value(requestIDKey).(string)
	return value
}

func WithActor(ctx context.Context, value Actor) context.Context {
	return context.WithValue(ctx, actorKey, value)
}

func ActorFrom(ctx context.Context) (Actor, bool) {
	value, ok := ctx.Value(actorKey).(Actor)
	return value, ok
}
