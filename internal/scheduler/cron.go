package scheduler

import (
	"fmt"
	"strings"
	"time"

	"github.com/robfig/cron/v3"
)

var fiveFieldParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)

func ValidateCron(expression, timezone string) error {
	if strings.TrimSpace(expression) == "" {
		return fmt.Errorf("cron expression is required")
	}
	if len(strings.Fields(expression)) != 5 {
		return fmt.Errorf("cron expression must use five fields")
	}
	if _, err := fiveFieldParser.Parse(expression); err != nil {
		return fmt.Errorf("invalid cron expression: %w", err)
	}
	if _, err := time.LoadLocation(timezone); err != nil {
		return fmt.Errorf("invalid timezone: %w", err)
	}
	return nil
}

func NextRun(expression, timezone string, after time.Time) (time.Time, error) {
	if err := ValidateCron(expression, timezone); err != nil {
		return time.Time{}, err
	}
	location, _ := time.LoadLocation(timezone)
	schedule, _ := fiveFieldParser.Parse(expression)
	return schedule.Next(after.In(location)).UTC(), nil
}

type DueResult struct {
	PlannedAt time.Time
	NextRunAt time.Time
}

func DueOccurrence(expression, timezone string, storedNext, now time.Time) (DueResult, bool, error) {
	if err := ValidateCron(expression, timezone); err != nil {
		return DueResult{}, false, err
	}
	if storedNext.After(now) {
		return DueResult{}, false, nil
	}
	next, err := NextRun(expression, timezone, now)
	if err != nil {
		return DueResult{}, false, err
	}
	return DueResult{PlannedAt: storedNext.UTC(), NextRunAt: next}, true, nil
}
