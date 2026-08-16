package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/supaapps/platform93/internal/buildinfo"
	"github.com/supaapps/platform93/internal/config"
	"github.com/supaapps/platform93/internal/database"
	"github.com/supaapps/platform93/internal/httpapi"
	"github.com/supaapps/platform93/internal/jobs"
	"github.com/supaapps/platform93/internal/observability"
	"github.com/supaapps/platform93/internal/platform"
	"github.com/supaapps/platform93/internal/secure"
)

func main() {
	if err := run(); err != nil {
		slog.Error("platform93 stopped", "error", err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: platform93 <serve|worker|dispatcher|migrate|doctor|version|bootstrap|recover|backup|restore>")
	}
	command := os.Args[1]
	if command == "version" {
		fmt.Printf("Platform93 %s (%s, %s)\n", buildinfo.Version, buildinfo.Commit, buildinfo.Date)
		return nil
	}
	if command == "migrate" || command == "doctor" || command == "backup" || command == "restore" {
		databaseURL, err := config.LoadDatabaseURL()
		if err != nil {
			return err
		}
		switch command {
		case "migrate":
			return database.Migrate(databaseURL)
		case "doctor":
			if err := database.Status(databaseURL); err != nil {
				return err
			}
			if err := database.ValidateAuthorization(databaseURL); err != nil {
				return err
			}
			fmt.Println("database: ready")
			fmt.Println("authorization: valid")
			return nil
		case "backup":
			if len(os.Args) != 3 {
				return fmt.Errorf("usage: platform93 backup <destination.dump>")
			}
			return database.Backup(context.Background(), databaseURL, os.Args[2], os.Stderr)
		case "restore":
			if len(os.Args) != 4 || os.Args[3] != "--confirm-replace" {
				return fmt.Errorf("usage: platform93 restore <source.dump> --confirm-replace")
			}
			return database.Restore(context.Background(), databaseURL, os.Args[2], os.Stderr)
		}
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	pool, err := database.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	vault, err := secure.NewVault(cfg.MasterKey)
	if err != nil {
		return err
	}
	app := platform.New(pool, vault, cfg.PublicURL)
	shutdownTracing, err := observability.SetupTracing(ctx, buildinfo.Version)
	if err != nil {
		return fmt.Errorf("configure OpenTelemetry: %w", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = shutdownTracing(shutdownCtx)
	}()
	if command == "worker" || command == "dispatcher" {
		go func() {
			if metricsErr := observability.RunMetricsServer(ctx, cfg.MetricsListenAddress); metricsErr != nil {
				slog.Error("metrics server stopped", "error", metricsErr)
				stop()
			}
		}()
	}
	switch command {
	case "bootstrap", "recover":
		token, err := app.CreateBootstrapCredential(ctx, command == "recover")
		if err != nil {
			return err
		}
		fmt.Println(token)
		return nil
	case "worker":
		return jobs.New(app).RunWorker(ctx)
	case "dispatcher":
		return jobs.New(app).RunDispatcher(ctx)
	case "serve":
		server := &http.Server{Addr: cfg.ListenAddress, Handler: httpapi.New(app, cfg.AdminAssets), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20}
		go func() {
			<-ctx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownGrace)
			defer cancel()
			_ = server.Shutdown(shutdownCtx)
		}()
		slog.Info("Platform93 API listening", "address", cfg.ListenAddress, "version", buildinfo.Version)
		err = server.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	default:
		return fmt.Errorf("unknown command %q", command)
	}
}
