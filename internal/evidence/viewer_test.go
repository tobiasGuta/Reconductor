package evidence

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/domain"
)

type authorizerFake struct {
	authorized artifact.AuthorizedEvidenceArtifactV1
	err        error
	calls      int
}

func (f *authorizerFake) AuthorizeEvidenceView(context.Context, domain.ID, domain.ID) (artifact.AuthorizedEvidenceArtifactV1, error) {
	f.calls++
	return f.authorized, f.err
}

type verifiedStoreFake struct {
	identity artifact.StoreIdentity
	open     func(domain.ResultArtifactRefV1) (io.ReadCloser, error)
	calls    int
}

func (f *verifiedStoreFake) Identity() artifact.StoreIdentity { return f.identity }
func (f *verifiedStoreFake) OpenVerified(_ context.Context, reference domain.ResultArtifactRefV1) (io.ReadCloser, error) {
	f.calls++
	return f.open(reference)
}

type closeErrorReader struct {
	io.Reader
	err    error
	closed *bool
}

func (r *closeErrorReader) Close() error {
	*r.closed = true
	return r.err
}

func TestReadReturnsBytesOnlyAfterCompleteVerification(t *testing.T) {
	content := []byte(`{"records":[{"status_code":200}]}`)
	authorized := authorizedFixture(t, content)
	authorizer := &authorizerFake{authorized: authorized}
	closed := false
	store := &verifiedStoreFake{
		identity: authorized.StoreIdentity,
		open: func(reference domain.ResultArtifactRefV1) (io.ReadCloser, error) {
			if reference != authorized.Reference {
				t.Fatalf("reference = %#v, want %#v", reference, authorized.Reference)
			}
			return &closeErrorReader{Reader: bytes.NewReader(content), closed: &closed}, nil
		},
	}

	verified, err := (Service{Authorizer: authorizer, Store: store}).Read(context.Background(), authorized.WorkflowRunID, authorized.Reference.ArtifactID)
	if err != nil {
		t.Fatal(err)
	}
	if !closed {
		t.Fatal("content returned before verified reader was closed")
	}
	if !bytes.Equal(verified.Content, content) || verified.Metadata.ArtifactID != authorized.Reference.ArtifactID || verified.Metadata.ContentSHA256 != authorized.Reference.ContentSHA256 {
		t.Fatalf("verified evidence = %#v", verified)
	}
}

func TestReadWithholdsBytesWhenEOFOrCloseVerificationFails(t *testing.T) {
	content := []byte("provider-derived-content")
	authorized := authorizedFixture(t, content)
	for _, test := range []struct {
		name string
		open func(domain.ResultArtifactRefV1) (io.ReadCloser, error)
	}{
		{
			name: "read verification",
			open: func(domain.ResultArtifactRefV1) (io.ReadCloser, error) {
				return &readErrorCloser{Reader: bytes.NewReader(content), err: errors.New("digest mismatch")}, nil
			},
		},
		{
			name: "close verification",
			open: func(domain.ResultArtifactRefV1) (io.ReadCloser, error) {
				closed := false
				return &closeErrorReader{Reader: bytes.NewReader(content), err: errors.New("digest mismatch"), closed: &closed}, nil
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &verifiedStoreFake{identity: authorized.StoreIdentity, open: test.open}
			result, err := (Service{Authorizer: &authorizerFake{authorized: authorized}, Store: store}).Read(context.Background(), authorized.WorkflowRunID, authorized.Reference.ArtifactID)
			if !errors.Is(err, artifact.ErrEvidenceVerificationFailed) {
				t.Fatalf("error = %v, want verification failure", err)
			}
			if len(result.Content) != 0 {
				t.Fatalf("unverified content was returned: %q", result.Content)
			}
			if strings.Contains(err.Error(), string(content)) {
				t.Fatal("failure message exposed provider-controlled content")
			}
		})
	}
}

func TestReadFailsClosedBeforeOpeningRestrictedForeignOrOversizedEvidence(t *testing.T) {
	content := []byte("ok")
	base := authorizedFixture(t, content)
	for _, test := range []struct {
		name       string
		authorized artifact.AuthorizedEvidenceArtifactV1
		authErr    error
		identity   artifact.StoreIdentity
		want       error
	}{
		{name: "restricted", authorized: base, authErr: artifact.ErrEvidenceRestricted, identity: base.StoreIdentity, want: artifact.ErrEvidenceRestricted},
		{name: "foreign incarnation", authorized: base, identity: artifact.StoreIdentity{ArtifactStoreID: base.StoreIdentity.ArtifactStoreID, IncarnationNonce: domain.NewID(), BackendKind: artifact.BackendKind, MarkerFormat: artifact.MarkerFormat, MarkerVersion: artifact.MarkerVersion}, want: artifact.ErrEvidenceUnavailable},
		{name: "oversized", authorized: withSize(base, domain.PreparedSetOutputAuthorityMaxBytes+1), identity: base.StoreIdentity, want: artifact.ErrEvidenceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &verifiedStoreFake{identity: test.identity, open: func(domain.ResultArtifactRefV1) (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(content)), nil
			}}
			result, err := (Service{Authorizer: &authorizerFake{authorized: test.authorized, err: test.authErr}, Store: store}).Read(context.Background(), base.WorkflowRunID, base.Reference.ArtifactID)
			if !errors.Is(err, test.want) || len(result.Content) != 0 {
				t.Fatalf("result=%#v error=%v want=%v", result, err, test.want)
			}
			if store.calls != 0 {
				t.Fatalf("store opened %d times", store.calls)
			}
		})
	}
}

func TestReadDistinguishesMissingFromFailedVerification(t *testing.T) {
	content := []byte("ok")
	authorized := authorizedFixture(t, content)
	for _, test := range []struct {
		name string
		err  error
		want error
	}{
		{name: "missing", err: os.ErrNotExist, want: artifact.ErrEvidenceUnavailable},
		{name: "unsafe inode", err: errors.New("unsafe inode"), want: artifact.ErrEvidenceVerificationFailed},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &verifiedStoreFake{identity: authorized.StoreIdentity, open: func(domain.ResultArtifactRefV1) (io.ReadCloser, error) {
				return nil, test.err
			}}
			result, err := (Service{Authorizer: &authorizerFake{authorized: authorized}, Store: store}).Read(context.Background(), authorized.WorkflowRunID, authorized.Reference.ArtifactID)
			if !errors.Is(err, test.want) || len(result.Content) != 0 {
				t.Fatalf("result=%#v error=%v want=%v", result, err, test.want)
			}
		})
	}
}

type readErrorCloser struct {
	Reader io.Reader
	err    error
}

func (r *readErrorCloser) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if errors.Is(err, io.EOF) {
		return n, r.err
	}
	return n, err
}
func (*readErrorCloser) Close() error { return nil }

func authorizedFixture(t *testing.T, content []byte) artifact.AuthorizedEvidenceArtifactV1 {
	t.Helper()
	artifactID := domain.NewID()
	storeID := domain.NewID()
	key, err := artifact.StorageKeyFor(artifactID)
	if err != nil {
		t.Fatal(err)
	}
	return artifact.AuthorizedEvidenceArtifactV1{
		Reference: domain.ResultArtifactRefV1{
			ArtifactID:       artifactID,
			ArtifactStoreID:  storeID,
			StorageKey:       key,
			Role:             domain.ArtifactRoleSemanticResult,
			ContentType:      "application/json",
			ContentSizeBytes: int64(len(content)),
			ContentSHA256:    artifact.DigestString(artifact.DigestBytes(content)),
		},
		StoreIdentity: artifact.StoreIdentity{ArtifactStoreID: storeID, IncarnationNonce: domain.NewID(), BackendKind: artifact.BackendKind, MarkerFormat: artifact.MarkerFormat, MarkerVersion: artifact.MarkerVersion},
		ProgramID:     domain.NewID(), TaskID: domain.NewID(), WorkflowRunID: domain.NewID(), StepRunID: domain.NewID(), StepDefinitionID: "probe",
		ToolRunID: domain.NewID(), ActionRequestID: domain.NewID(), ProviderAttemptID: domain.NewID(), ResultOccurrenceID: domain.NewID(), PublicationID: domain.NewID(),
		CapabilityName: "probe.http", CapabilityVersion: "1", ProviderName: "httpx", ArtifactType: "normalized-result", SemanticCompleteness: domain.SemanticComplete,
	}
}

func withSize(value artifact.AuthorizedEvidenceArtifactV1, size int64) artifact.AuthorizedEvidenceArtifactV1 {
	value.Reference.ContentSizeBytes = size
	return value
}
