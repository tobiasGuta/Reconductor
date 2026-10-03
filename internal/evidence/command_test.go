package evidence

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/domain"
)

func TestExecuteListsAndDisplaysThroughService(t *testing.T) {
	content := []byte("recorded\nobservation")
	authorized := authorizedFixture(t, content)
	store := &verifiedStoreFake{identity: authorized.StoreIdentity, open: func(domain.ResultArtifactRefV1) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(content)), nil
	}}
	service := Service{Authorizer: &authorizerFake{authorized: authorized}, Lister: &listerFake{items: []artifact.AuthorizedEvidenceArtifactV1{authorized}}, Store: store}

	var list bytes.Buffer
	if err := Execute(context.Background(), service, []string{string(authorized.WorkflowRunID)}, &list); err != nil {
		t.Fatal(err)
	}
	var items []Metadata
	if err := json.Unmarshal(list.Bytes(), &items); err != nil || len(items) != 1 || items[0].ArtifactID != authorized.Reference.ArtifactID {
		t.Fatalf("list=%s items=%#v error=%v", list.String(), items, err)
	}
	if strings.Contains(list.String(), authorized.Reference.StorageKey) || strings.Contains(list.String(), "storage_key") {
		t.Fatalf("list exposed storage data: %s", list.String())
	}

	var shown bytes.Buffer
	if err := Execute(context.Background(), service, []string{string(authorized.WorkflowRunID), string(authorized.Reference.ArtifactID)}, &shown); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(shown.String(), "integrity_status: verified") || !strings.Contains(shown.String(), "| recorded\n| observation") {
		t.Fatalf("display=%s", shown.String())
	}
}

func TestExecuteReturnsNoOutputOnReadOrCloseVerificationFailure(t *testing.T) {
	content := []byte("provider-secret")
	authorized := authorizedFixture(t, content)
	for _, open := range []func(domain.ResultArtifactRefV1) (io.ReadCloser, error){
		func(domain.ResultArtifactRefV1) (io.ReadCloser, error) {
			return &readErrorCloser{Reader: bytes.NewReader(content), err: errors.New("read failed")}, nil
		},
		func(domain.ResultArtifactRefV1) (io.ReadCloser, error) {
			closed := false
			return &closeErrorReader{Reader: bytes.NewReader(content), err: errors.New("close failed"), closed: &closed}, nil
		},
	} {
		var output bytes.Buffer
		service := Service{Authorizer: &authorizerFake{authorized: authorized}, Store: &verifiedStoreFake{identity: authorized.StoreIdentity, open: open}}
		err := Execute(context.Background(), service, []string{string(authorized.WorkflowRunID), string(authorized.Reference.ArtifactID)}, &output)
		if !errors.Is(err, artifact.ErrEvidenceVerificationFailed) || output.Len() != 0 {
			t.Fatalf("output=%q error=%v", output.String(), err)
		}
	}
}

func TestExecuteRejectsInvalidUnknownRestrictedAndCrossRunWithoutOutput(t *testing.T) {
	content := []byte("secret")
	authorized := authorizedFixture(t, content)
	requests := []struct {
		name string
		args []string
		err  error
	}{
		{name: "invalid run", args: []string{"NOT-A-UUID"}, err: artifact.ErrEvidenceUnavailable},
		{name: "invalid artifact", args: []string{string(authorized.WorkflowRunID), "NOT-A-UUID"}, err: artifact.ErrEvidenceUnavailable},
		{name: "unknown", args: []string{string(authorized.WorkflowRunID), string(domain.NewID())}, err: artifact.ErrEvidenceUnavailable},
		{name: "restricted", args: []string{string(authorized.WorkflowRunID), string(authorized.Reference.ArtifactID)}, err: artifact.ErrEvidenceRestricted},
		{name: "cross run", args: []string{string(domain.NewID()), string(authorized.Reference.ArtifactID)}, err: artifact.ErrEvidenceUnavailable},
	}
	for _, test := range requests {
		t.Run(test.name, func(t *testing.T) {
			authorizer := &authorizerFake{authorized: authorized, err: test.err}
			var output bytes.Buffer
			service := Service{Authorizer: authorizer, Lister: &listerFake{err: test.err}, Store: &verifiedStoreFake{identity: authorized.StoreIdentity}}
			err := Execute(context.Background(), service, test.args, &output)
			if !errors.Is(err, test.err) || output.Len() != 0 {
				t.Fatalf("output=%q error=%v want=%v", output.String(), err, test.err)
			}
		})
	}
}

func TestExecuteEmptyRunIsConciseJSON(t *testing.T) {
	identity := artifact.StoreIdentity{ArtifactStoreID: domain.NewID(), IncarnationNonce: domain.NewID(), BackendKind: artifact.BackendKind, MarkerFormat: artifact.MarkerFormat, MarkerVersion: artifact.MarkerVersion}
	var output bytes.Buffer
	err := Execute(context.Background(), Service{Lister: &listerFake{items: []artifact.AuthorizedEvidenceArtifactV1{}}, Store: &verifiedStoreFake{identity: identity}}, []string{string(domain.NewID())}, &output)
	if err != nil || strings.TrimSpace(output.String()) != "[]" {
		t.Fatalf("output=%q error=%v", output.String(), err)
	}
}
