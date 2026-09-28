package main

import (
	"context"
	"os"

	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/config"
	"github.com/tobiasGuta/Reconductor/internal/evidence"
)

func runEvidenceCommand(ctx context.Context, cfg config.Config, args []string) error {
	storeID, err := cfg.ArtifactStorage.RequiredStoreID()
	if err != nil {
		return err
	}
	store, err := readyStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer store.Close()

	local, err := artifact.OpenLocal(ctx, cfg.ArtifactStorage.Root, storeID, store, nil)
	if err != nil {
		return artifact.ErrEvidenceUnavailable
	}
	service := evidence.Service{Authorizer: store, Lister: store, Store: local}
	return evidence.Execute(ctx, service, args, os.Stdout)
}
