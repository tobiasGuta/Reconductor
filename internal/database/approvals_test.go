package database

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/domain"
)

func TestApprovalUUIDCanonicalizesDatabaseValues(t *testing.T) {
	taskBytes := [16]byte{204, 142, 44, 194, 200, 121, 65, 87, 170, 65, 224, 153, 161, 97, 29, 187}
	tests := []struct {
		name  string
		value any
		want  domain.ID
	}{
		{"database byte array", taskBytes, "cc8e2cc2-c879-4157-aa41-e099a1611dbb"},
		{"database byte slice", taskBytes[:], "cc8e2cc2-c879-4157-aa41-e099a1611dbb"},
		{"uppercase string", "CC8E2CC2-C879-4157-AA41-E099A1611DBB", "cc8e2cc2-c879-4157-aa41-e099a1611dbb"},
		{"domain ID", domain.ID("cc8e2cc2-c879-4157-aa41-e099a1611dbb"), "cc8e2cc2-c879-4157-aa41-e099a1611dbb"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := approvalUUID(test.value, "task_id", false)
			if err != nil {
				t.Fatal(err)
			}
			if got == nil || *got != test.want {
				t.Fatalf("UUID=%v want=%q", got, test.want)
			}
		})
	}
}

func TestAssignApprovalUUIDsCoversEveryApprovalIdentifier(t *testing.T) {
	var item ApprovalListItem
	err := assignApprovalUUIDs(
		&item,
		[16]byte{0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x43, 0x33, 0x84, 0x44, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55},
		[16]byte{0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0x4c, 0xcc, 0x8d, 0xdd, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee},
		[16]byte{0xcc, 0x8e, 0x2c, 0xc2, 0xc8, 0x79, 0x41, 0x57, 0xaa, 0x41, 0xe0, 0x99, 0xa1, 0x61, 0x1d, 0xbb},
		[16]byte{0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0x4c, 0xcc, 0x8d, 0xdd, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee},
	)
	if err != nil {
		t.Fatal(err)
	}
	if item.ID != "11111111-2222-4333-8444-555555555555" ||
		item.RequestID != "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" ||
		item.ActionRequestID != "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" ||
		item.TaskID != "cc8e2cc2-c879-4157-aa41-e099a1611dbb" {
		t.Fatalf("approval UUIDs were not all canonicalized: %#v", item)
	}
}

func TestApprovalUUIDPreservesOptionalNull(t *testing.T) {
	got, err := approvalUUID(nil, "optional_id", true)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("optional UUID=%q want nil", *got)
	}
	raw, err := json.Marshal(struct {
		OptionalID *domain.ID `json:"optional_id"`
	}{OptionalID: got})
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"optional_id":null}` {
		t.Fatalf("optional UUID JSON=%s want explicit null", raw)
	}
}

func TestApprovalUUIDRejectsMalformedValues(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  string
	}{
		{"short bytes", []byte{1, 2, 3}, "UUID byte length is 3, want 16"},
		{"missing required", nil, "UUID is required"},
		{"malformed string", "not-a-uuid", "8-4-4-4-12 canonical form"},
		{"wrong type", 42, "unsupported UUID value type int"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := approvalUUID(test.value, "id", false); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err=%v want containing %q", err, test.want)
			}
		})
	}
}
