package evidence

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/domain"
)

type listerFake struct {
	items []artifact.AuthorizedEvidenceArtifactV1
	err   error
	calls int
}

func (f *listerFake) ListEvidenceView(context.Context, domain.ID) ([]artifact.AuthorizedEvidenceArtifactV1, error) {
	f.calls++
	return f.items, f.err
}

func TestListProjectsOnlySafeAuthorizedMetadata(t *testing.T) {
	authorized := authorizedFixture(t, []byte("ok"))
	lister := &listerFake{items: []artifact.AuthorizedEvidenceArtifactV1{authorized}}
	store := &verifiedStoreFake{identity: authorized.StoreIdentity}
	items, err := (Service{Lister: lister, Store: store}).List(context.Background(), authorized.WorkflowRunID)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].ArtifactID != authorized.Reference.ArtifactID || items[0].IntegrityStatus != "not_checked" || items[0].AccessStatus != "permitted" || items[0].PublicationState != "adopted" {
		t.Fatalf("metadata = %#v", items)
	}
	if store.calls != 0 {
		t.Fatalf("list opened artifact content %d times", store.calls)
	}
	encoded, err := json.Marshal(items)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{authorized.Reference.StorageKey, "storage_key", "storage_location", "path"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("list exposed %q: %s", forbidden, encoded)
		}
	}
}

func TestListFailsClosedForUnknownRunOrStoreIdentity(t *testing.T) {
	authorized := authorizedFixture(t, []byte("ok"))
	otherIdentity := authorized.StoreIdentity
	otherIdentity.IncarnationNonce = domain.NewID()
	for _, test := range []struct {
		name   string
		lister *listerFake
		store  *verifiedStoreFake
	}{
		{name: "unknown run", lister: &listerFake{err: artifact.ErrEvidenceUnavailable}, store: &verifiedStoreFake{identity: authorized.StoreIdentity}},
		{name: "foreign store", lister: &listerFake{items: []artifact.AuthorizedEvidenceArtifactV1{authorized}}, store: &verifiedStoreFake{identity: otherIdentity}},
	} {
		t.Run(test.name, func(t *testing.T) {
			items, err := (Service{Lister: test.lister, Store: test.store}).List(context.Background(), authorized.WorkflowRunID)
			if !errors.Is(err, artifact.ErrEvidenceUnavailable) || items != nil {
				t.Fatalf("items=%#v error=%v", items, err)
			}
		})
	}
}
