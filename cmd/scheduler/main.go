package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/tobiasGuta/Reconductor/internal/config"
	"github.com/tobiasGuta/Reconductor/internal/database"
	"github.com/tobiasGuta/Reconductor/internal/orchestration"
	"github.com/tobiasGuta/Reconductor/internal/providers"
	"github.com/tobiasGuta/Reconductor/internal/scheduler"
)

func main() {
	if err := run(); err != nil && !errors.Is(err, context.Canceled) {
		slog.Error("scheduler failed", "error", err)
		os.Exit(1)
	}
}

func run() error {
	_ = config.LoadEnvFile(".env")
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	store, err := database.Open(ctx, cfg.Database.URL)
	if err != nil {
		return err
	}
	defer store.Close()
	if err := store.Migrate(ctx); err != nil {
		return err
	}
	registry := providers.Registry(cfg)
	orchestrator := &orchestration.Service{Config: cfg, Store: store, Registry: registry}
	service := scheduler.New(store, orchestrator, cfg.Scheduler)
	slog.Info("Reconductor scheduler ready", "poll_interval", cfg.Scheduler.PollInterval, "max_concurrent_runs", cfg.Scheduler.MaxConcurrentRuns)
	return service.Run(ctx)
}
