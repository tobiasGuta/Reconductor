package scheduler

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	platformscope "github.com/tobiasGuta/Reconductor/internal/scope"
	"github.com/tobiasGuta/Reconductor/internal/targeting"
	"github.com/tobiasGuta/Reconductor/internal/workflow"
	"github.com/tobiasGuta/Reconductor/internal/workflows"
)

type ProgramReader interface {
	GetProgram(context.Context, domain.ID) (domain.Program, error)
}

type ScheduleValidator struct {
	Programs  ProgramReader
	Registry  *capability.Registry
	ScopeRoot string
}

func (v ScheduleValidator) Validate(ctx context.Context, item domain.Schedule, after time.Time) (domain.Schedule, error) {
	item.Name = strings.TrimSpace(item.Name)
	item.WorkflowName = strings.TrimSpace(item.WorkflowName)
	item.Objective = strings.TrimSpace(item.Objective)
	item.CronExpression = strings.TrimSpace(item.CronExpression)
	item.Timezone = strings.TrimSpace(item.Timezone)
	if item.ProgramID == "" {
		return domain.Schedule{}, fmt.Errorf("program_id is required")
	}
	if item.Name == "" {
		return domain.Schedule{}, fmt.Errorf("schedule name is required")
	}
	if item.Objective == "" {
		return domain.Schedule{}, fmt.Errorf("schedule objective is required")
	}
	if item.WorkflowName == "" {
		return domain.Schedule{}, fmt.Errorf("workflow name is required")
	}
	if err := ValidateCron(item.CronExpression, item.Timezone); err != nil {
		return domain.Schedule{}, err
	}
	if v.Programs == nil || v.Registry == nil {
		return domain.Schedule{}, fmt.Errorf("schedule validation is unavailable")
	}
	program, err := v.Programs.GetProgram(ctx, item.ProgramID)
	if err != nil {
		return domain.Schedule{}, fmt.Errorf("load program: %w", err)
	}
	scope, err := platformscope.LoadBurpReference(program.ScopeReference, v.ScopeRoot)
	if err != nil {
		return domain.Schedule{}, fmt.Errorf("load current scope: %w", err)
	}
	plan, err := targeting.Plan(scope, nil)
	if err != nil {
		return domain.Schedule{}, err
	}
	if !plan.HasExecutableTargets() {
		return domain.Schedule{}, fmt.Errorf("target plan has no executable authorized targets")
	}
	definition, err := workflows.Build(item.WorkflowName, plan, item.Headless)
	if err != nil {
		return domain.Schedule{}, err
	}
	if err := workflow.Validate(definition, v.Registry); err != nil {
		return domain.Schedule{}, err
	}
	next, err := NextRun(item.CronExpression, item.Timezone, after)
	if err != nil {
		return domain.Schedule{}, err
	}
	item.NextRunAt = next
	return item, nil
}
