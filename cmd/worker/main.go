package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/budget"
	"github.com/tobiasGuta/Reconductor/internal/config"
	"github.com/tobiasGuta/Reconductor/internal/database"
	"github.com/tobiasGuta/Reconductor/internal/doctor"
	"github.com/tobiasGuta/Reconductor/internal/policy"
	"github.com/tobiasGuta/Reconductor/internal/providers"
	"github.com/tobiasGuta/Reconductor/internal/queue"
	"github.com/tobiasGuta/Reconductor/internal/redaction"
	"github.com/tobiasGuta/Reconductor/internal/worker"
)

func main() {
	if err := run(); err != nil {
		slog.Error("worker stopped", "error", err)
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
	providerChecks := doctor.CheckProviderEnvironment(ctx, cfg, nil)
	if failures := doctor.Failures(providerChecks, true); len(failures) > 0 {
		for _, failure := range failures {
			slog.Error("worker environment check failed", "component", failure.Component, "status", failure.Status, "details", failure.Details)
		}
		return fmt.Errorf("worker environment is incomplete: %d provider checks failed", len(failures))
	}
	store, err := database.Open(ctx, cfg.Database.URL)
	if err != nil {
		return err
	}
	defer store.Close()
	if err := store.RequireCurrentSchema(ctx); err != nil {
		return err
	}
	opts := &redis.Options{Addr: cfg.Redis.Address, Username: cfg.Redis.Username, Password: cfg.Redis.Password, DB: cfg.Redis.DB, DialTimeout: 5 * time.Second, ReadTimeout: cfg.Worker.ReadBlock + time.Second, WriteTimeout: 5 * time.Second}
	if cfg.Redis.TLS {
		opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	rdb := redis.NewClient(opts)
	defer rdb.Close()
	if err := rdb.Ping(ctx).Err(); err != nil {
		return err
	}
	artifacts, err := artifact.OpenLocal(ctx, cfg.ArtifactStorage.Root, storeID, store, redaction.New(cfg.Logging.SecretNames...))
	if err != nil {
		return err
	}
	store.ConfigureExactReviewEvidenceReader(artifacts)
	prepared, err := store.RequirePreparedEvidenceReady(ctx, storeID)
	if err != nil {
		return fmt.Errorf("prepared evidence readiness: %w", err)
	}
	workerPolicy := policy.Policy{RateLimit: cfg.Policy.DefaultRateLimit, Concurrency: cfg.Policy.DefaultConcurrency}
	limiter := budget.NewLocal(budget.Limits{Program: policy.ProgramParallelism(workerPolicy), Provider: cfg.Policy.DefaultProviderConcurrency, Host: cfg.Policy.DefaultHostConcurrency})
	service := worker.Service{Queue: queue.New(rdb, cfg.Worker.ConsumerGroup, cfg.Worker.ConsumerName, cfg.Worker.MaxRetries, cfg.Worker.RetryBase), Registry: providers.Registry(cfg), Artifacts: artifacts, Results: store, PoolSize: cfg.Worker.PoolSize, ReadBlock: cfg.Worker.ReadBlock, LeaseTimeout: cfg.Worker.LeaseTimeout, Logger: slog.Default(), Budget: limiter, PolicyAuditor: store}
	slog.Info("worker started", "config", cfg.String(), "prepared_open_sets", prepared.OpenSets, "prepared_max_open_sets", prepared.MaxOpenSets, "prepared_unresolved_bytes", prepared.UnresolvedBytes, "prepared_max_unresolved_bytes", prepared.MaxUnresolvedBytes)
	return service.Run(ctx)
}
