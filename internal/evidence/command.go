package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/domain"
)

// Execute is the run-scoped CLI-to-service path. Args contain the workflow run
// ID and, for display, an optional artifact ID.
func Execute(ctx context.Context, service Service, args []string, output io.Writer) error {
	if len(args) < 1 || len(args) > 2 {
		return fmt.Errorf("usage: platform run evidence <workflow-run-id> [artifact-id]")
	}
	workflowRunID, err := domain.ParseID(args[0])
	if err != nil {
		return artifact.ErrEvidenceUnavailable
	}
	if len(args) == 1 {
		items, err := service.List(ctx, workflowRunID)
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(output)
		encoder.SetIndent("", "  ")
		return encoder.Encode(items)
	}

	artifactID, err := domain.ParseID(args[1])
	if err != nil {
		return artifact.ErrEvidenceUnavailable
	}
	verified, err := service.Read(ctx, workflowRunID, artifactID)
	if err != nil {
		return err
	}
	_, err = RenderVerified(output, verified)
	return err
}
