package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

type Config struct {
	DatabaseURL          string
	PublicURL            string
	ListenAddress        string
	AdminAssets          string
	MetricsListenAddress string
	MasterKey            []byte
	ShutdownGrace        time.Duration
}

func Load() (Config, error) {
	databaseURL, err := LoadDatabaseURL()
	if err != nil {
		return Config{}, err
	}
	c := Config{
		DatabaseURL:          databaseURL,
		PublicURL:            strings.TrimRight(env("PLATFORM93_PUBLIC_URL", "http://localhost:8093"), "/"),
		ListenAddress:        env("PLATFORM93_LISTEN_ADDRESS", ":8093"),
		AdminAssets:          env("PLATFORM93_ADMIN_ASSETS", "web/out"),
		MetricsListenAddress: env("PLATFORM93_METRICS_LISTEN_ADDRESS", ":9090"),
		ShutdownGrace:        20 * time.Second,
	}
	key, err := loadMasterKey()
	if err != nil {
		return Config{}, err
	}
	c.MasterKey = key
	return c, nil
}

func LoadDatabaseURL() (string, error) {
	databaseURL, err := envOrFile("PLATFORM93_DATABASE_URL", "PLATFORM93_DATABASE_URL_FILE")
	if err != nil {
		return "", err
	}
	if databaseURL == "" {
		return "", errors.New("PLATFORM93_DATABASE_URL is required")
	}
	return databaseURL, nil
}

func envOrFile(valueName, fileName string) (string, error) {
	if value := os.Getenv(valueName); value != "" {
		return value, nil
	}
	if path := os.Getenv(fileName); path != "" {
		value, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", fileName, err)
		}
		return strings.TrimSpace(string(value)), nil
	}
	return "", nil
}

func loadMasterKey() ([]byte, error) {
	if path := os.Getenv("PLATFORM93_MASTER_KEY_FILE"); path != "" {
		value, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read master key: %w", err)
		}
		return decodeKey(strings.TrimSpace(string(value)))
	}
	return decodeKey(os.Getenv("PLATFORM93_MASTER_KEY"))
}

func decodeKey(value string) ([]byte, error) {
	if value == "" {
		return nil, errors.New("PLATFORM93_MASTER_KEY or PLATFORM93_MASTER_KEY_FILE is required")
	}
	key, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(key) != 32 {
		return nil, errors.New("Platform93 master key must be base64-encoded 32 bytes")
	}
	return key, nil
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
