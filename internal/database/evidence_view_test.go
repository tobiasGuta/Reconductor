package database

import (
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/tobiasGuta/Reconductor/internal/domain"
)

func TestEvidenceViewUsesRepeatableReadOnlyTransaction(t *testing.T) {
	if evidenceViewTxOptions.IsoLevel != pgx.RepeatableRead {
		t.Fatalf("isolation = %q, want %q", evidenceViewTxOptions.IsoLevel, pgx.RepeatableRead)
	}
	if evidenceViewTxOptions.AccessMode != pgx.ReadOnly {
		t.Fatalf("access mode = %q, want %q", evidenceViewTxOptions.AccessMode, pgx.ReadOnly)
	}
}

func TestRecognizedEvidenceRolesAreClosed(t *testing.T) {
	for _, role := range []domain.ResultArtifactRoleV1{
		domain.ArtifactRoleProviderStdout,
		domain.ArtifactRoleProviderStderr,
		domain.ArtifactRoleProviderDiagnostic,
		domain.ArtifactRoleSemanticResult,
	} {
		if !recognizedEvidenceRole(role) {
			t.Fatalf("recognized role %q was rejected", role)
		}
	}
	if recognizedEvidenceRole("forensic_capture") {
		t.Fatal("unrecognized evidence role was accepted")
	}
}
