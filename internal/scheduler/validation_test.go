package scheduler

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/config"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/providers"
	"github.com/tobiasGuta/Reconductor/internal/workflows"
)

type validationProgramReader struct {
	program domain.Program
}

func (r validationProgramReader) GetProgram(context.Context, domain.ID) (domain.Program, error) {
	return r.program, nil
}

func TestScheduleValidatorUsesProgramScopeAndWorkflowRegistry(t *testing.T) {
	scopePath := filepath.Join(t.TempDir(), "scope.json")
	scopeJSON := `{"target":{"scope":{"advanced_mode":true,"exclude":[],"include":[{"enabled":true,"file":"^/.*","host":"^app\\.example\\.test$","port":"^443$","protocol":"https"}]}}}`
	if err := os.WriteFile(scopePath, []byte(scopeJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	programID := domain.NewID()
	validator := ScheduleValidator{
		Programs: validationProgramReader{program: domain.Program{ID: programID, ScopeReference: scopePath}},
		Registry: providers.Registry(config.Config{}),
	}
	item := domain.Schedule{
		ProgramID: programID, Name: " daily ", WorkflowName: workflows.ContinuousName,
		Objective: " authorized reconnaissance ", CronExpression: "0 9 * * *", Timezone: "UTC",
	}
	validated, err := validator.Validate(context.Background(), item, time.Date(2026, 7, 29, 8, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if validated.Name != "daily" || validated.Objective != "authorized reconnaissance" || validated.NextRunAt.IsZero() {
		t.Fatalf("validated schedule = %#v", validated)
	}

	item.WorkflowName = workflows.BaselineName
	if _, err := validator.Validate(context.Background(), item, time.Now()); err != nil {
		t.Fatalf("authorized web baseline was rejected: %v", err)
	}
	item.WorkflowName = "unsupported"
	if _, err := validator.Validate(context.Background(), item, time.Now()); err == nil {
		t.Fatal("unsupported workflow was accepted")
	}
	item.WorkflowName = workflows.ContinuousName
	item.Name = " "
	if _, err := validator.Validate(context.Background(), item, time.Now()); err == nil {
		t.Fatal("empty name was accepted")
	}
}
