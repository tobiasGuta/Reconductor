package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/config"
	"github.com/tobiasGuta/Reconductor/internal/database"
	"github.com/tobiasGuta/Reconductor/internal/orchestration"
	"github.com/tobiasGuta/Reconductor/internal/providers"
	"github.com/tobiasGuta/Reconductor/internal/redaction"
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
	storeID, err := cfg.ArtifactStorage.RequiredStoreID()
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
	if err := store.RequireCurrentSchema(ctx); err != nil {
		return err
	}
	artifacts, err := artifact.OpenLocal(ctx, cfg.ArtifactStorage.Root, storeID, store, redaction.New(cfg.Logging.SecretNames...))
	if err != nil {
		return err
	}
	prepared, err := store.RequirePreparedEvidenceReady(ctx, storeID)
	if err != nil {
		return fmt.Errorf("prepared evidence readiness: %w", err)
	}
	registry := providers.Registry(cfg)
	orchestrator := &orchestration.Service{Config: cfg, Store: store, Registry: registry, Artifacts: artifacts}
	service := scheduler.New(store, orchestrator, cfg.Scheduler)
	slog.Info("Reconductor scheduler ready", "poll_interval", cfg.Scheduler.PollInterval, "max_concurrent_runs", cfg.Scheduler.MaxConcurrentRuns, "prepared_open_sets", prepared.OpenSets, "prepared_max_open_sets", prepared.MaxOpenSets, "prepared_unresolved_bytes", prepared.UnresolvedBytes, "prepared_max_unresolved_bytes", prepared.MaxUnresolvedBytes)
	return service.Run(ctx)
}
