package policy

import (
	"testing"
	"time"
)

func TestCurrentScanWindowDeadline(t *testing.T) {
	at := time.Date(2026, 9, 29, 16, 30, 22, 0, time.UTC)
	deadline, err := CurrentScanWindowDeadline([]string{"09:00-17:00 UTC"}, at)
	if err != nil || deadline == nil || !deadline.Equal(time.Date(2026, 9, 29, 17, 0, 0, 0, time.UTC)) {
		t.Fatalf("deadline=%v err=%v", deadline, err)
	}
	if _, err := CurrentScanWindowDeadline([]string{"09:00-17:00 UTC"}, deadline.Add(time.Second)); err == nil {
		t.Fatal("accepted expired scan window")
	}
	if deadline, err := CurrentScanWindowDeadline(nil, at); err != nil || deadline != nil {
		t.Fatalf("unbounded deadline=%v err=%v", deadline, err)
	}
}
