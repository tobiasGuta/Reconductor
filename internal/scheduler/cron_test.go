package scheduler

import (
	"testing"
	"time"
)

func TestValidateCronFiveFields(t *testing.T) {
	if err := ValidateCron("0 9 * * 1", "UTC"); err != nil {
		t.Fatal(err)
	}
}

func TestValidateCronRejectsInvalidAndSixField(t *testing.T) {
	if err := ValidateCron("", "UTC"); err == nil {
		t.Fatal("expected empty expression rejection")
	}
	if err := ValidateCron("not cron", "UTC"); err == nil {
		t.Fatal("expected invalid expression rejection")
	}
	if err := ValidateCron("0 0 9 * * 1", "UTC"); err == nil {
		t.Fatal("expected six-field expression rejection")
	}
	if err := ValidateCron("0 9 * * 1", "Mars/Olympus"); err == nil {
		t.Fatal("expected invalid timezone rejection")
	}
}

func TestNextRunUTC(t *testing.T) {
	next, err := NextRun("0 9 * * 1", "UTC", time.Date(2026, 7, 27, 8, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 7, 27, 9, 0, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Fatalf("next=%s want %s", next, want)
	}
}

func TestNextRunNewYorkSpringDST(t *testing.T) {
	next, err := NextRun("30 2 * * *", "America/New_York", time.Date(2026, 3, 8, 6, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	location, _ := time.LoadLocation("America/New_York")
	local := next.In(location)
	if local.Day() != 9 || local.Hour() != 2 || local.Minute() != 30 {
		t.Fatalf("next local=%s", local)
	}
}

func TestNextRunNewYorkFallDST(t *testing.T) {
	next, err := NextRun("30 1 * * *", "America/New_York", time.Date(2026, 11, 1, 4, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	location, _ := time.LoadLocation("America/New_York")
	local := next.In(location)
	if local.Day() != 1 || local.Hour() != 1 || local.Minute() != 30 {
		t.Fatalf("next local=%s", local)
	}
}

func TestDueOccurrenceMaterializesOneCatchup(t *testing.T) {
	stored := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	due, ok, err := DueOccurrence("0 9 * * *", "UTC", stored, now)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected overdue occurrence")
	}
	if !due.PlannedAt.Equal(stored) {
		t.Fatalf("planned=%s want stored missed occurrence %s", due.PlannedAt, stored)
	}
	if !due.NextRunAt.After(now) {
		t.Fatalf("next_run_at=%s should be after now=%s", due.NextRunAt, now)
	}
}
