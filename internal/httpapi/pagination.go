package httpapi

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type timeCursor struct {
	Time time.Time
	ID   string
}

func pageLimit(r *http.Request) int {
	limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || limit <= 0 {
		return 50
	}
	if limit > 100 {
		return 100
	}
	return limit
}

func decodeTimeCursor(value string) (timeCursor, error) {
	if value == "" {
		return timeCursor{Time: time.Now().UTC().Add(time.Second), ID: "ffffffff-ffff-ffff-ffff-ffffffffffff"}, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return timeCursor{}, fmt.Errorf("invalid cursor")
	}
	parts := strings.SplitN(string(decoded), "|", 2)
	if len(parts) != 2 {
		return timeCursor{}, fmt.Errorf("invalid cursor")
	}
	timestamp, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil || parts[1] == "" {
		return timeCursor{}, fmt.Errorf("invalid cursor")
	}
	return timeCursor{Time: timestamp, ID: parts[1]}, nil
}

func encodeTimeCursor(timestamp time.Time, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(timestamp.UTC().Format(time.RFC3339Nano) + "|" + id))
}
