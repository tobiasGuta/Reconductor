//go:build linux

package artifact

import (
	"context"
	"errors"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func linuxGuard(t *testing.T) (*Local, *localPublisherGuard) {
	t.Helper()
	_, local := initializedLocal(t)
	guard, err := local.AcquirePublisher(context.Background(), local.Identity())
	if errors.Is(err, ErrPreparedStoreUnsupported) {
		t.Skipf("unsupported test filesystem: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { guard.Close() })
	return local, guard.(*localPublisherGuard)
}

func reservedFixture(storeID domain.ID, data string) ReservedArtifactV1 {
	id := domain.NewID()
	key, _ := StorageKeyFor(id)
	return ReservedArtifactV1{PublicationID: domain.NewID(), ArtifactID: id, ArtifactStoreID: storeID, StorageKey: key, ExpectedSize: int64(len(data)), ExpectedSHA256: DigestBytes([]byte(data))}
}

func TestPinnedPublicationRootReplacementAndCompetingGuard(t *testing.T) {
	local, g := linuxGuard(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if guard, err := local.AcquirePreparedRecovery(ctx, local.Identity()); err == nil {
		guard.Close()
		t.Fatal("exclusive recovery competed with live publisher")
	}
	old := local.root + "-original"
	if err := os.Rename(local.root, old); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Remove(local.root); err != nil {
			t.Error(err)
		}
		if err := os.Rename(old, local.root); err != nil {
			t.Error(err)
		}
	})
	if err := os.Mkdir(local.root, 0700); err != nil {
		t.Fatal(err)
	}
	r := reservedFixture(g.identity.ArtifactStoreID, "exact")
	if _, err := g.PublishReserved(context.Background(), r, strings.NewReader("exact")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(local.root, filepath.FromSlash(r.StorageKey))); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("publication followed replaced root")
	}
	if _, err := os.Stat(filepath.Join(old, filepath.FromSlash(r.StorageKey))); err != nil {
		t.Fatal(err)
	}
	if guard, err := local.AcquirePublisher(context.Background(), local.Identity()); err == nil {
		guard.Close()
		t.Fatal("replacement root regained store authority")
	}
}

func TestPinnedPublicationRejectsIntermediateSymlink(t *testing.T) {
	local, g := linuxGuard(t)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(local.root, "v1")); err != nil {
		t.Fatal(err)
	}
	r := reservedFixture(g.identity.ArtifactStoreID, "exact")
	if _, err := g.PublishReserved(context.Background(), r, strings.NewReader("exact")); err == nil {
		t.Fatal("publication followed intermediate symlink")
	}
	entries, err := os.ReadDir(outside)
	if err != nil || len(entries) != 0 {
		t.Fatal("symlink target modified")
	}
}

func TestPinnedFinalReadRejectsHardlink(t *testing.T) {
	local, g := linuxGuard(t)
	r := reservedFixture(g.identity.ArtifactStoreID, "exact")
	if _, err := g.PublishReserved(context.Background(), r, strings.NewReader("exact")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(local.root, filepath.FromSlash(r.StorageKey)), filepath.Join(local.root, "extra-link")); err != nil {
		t.Fatal(err)
	}
	if reader, err := openPreparedVerified(context.Background(), g.rootFD, r.StorageKey, r.ExpectedSize, r.ExpectedSHA256); err == nil {
		reader.Close()
		t.Fatal("authoritative read accepted hardlink")
	}
}

func TestPreparedPhysicalWriteCeilingAndPartialFailure(t *testing.T) {
	_, g := linuxGuard(t)
	setID := domain.NewID()
	remaining := int64(10)
	for ordinal, data := range []string{"1234", strings.Repeat("x", 100)} {
		key, _ := domain.PreparedMemberKey(setID, ordinal)
		n, err := writePreparedExclusive(g.rootFD, key, strings.NewReader(data), 4, DigestBytes([]byte("1234")), remaining)
		remaining -= n
		if remaining < 0 {
			t.Fatal("physical quota exceeded")
		}
		if ordinal == 1 && !errors.Is(err, ErrPreparedCapacityExceeded) {
			t.Fatalf("overflow=%v", err)
		}
	}
	if remaining != 0 {
		t.Fatalf("remaining=%d", remaining)
	}
}

func TestResolvedCleanupResumesAfterEveryUnlink(t *testing.T) {
	for stopped := 0; stopped <= 3; stopped++ {
		t.Run(string(rune('0'+stopped)), func(t *testing.T) {
			local, publisher := linuxGuard(t)
			publisher.Close()
			guard, err := local.AcquirePreparedRecovery(context.Background(), local.Identity())
			if err != nil {
				t.Fatal(err)
			}
			defer guard.Close()
			g := guard.(*localPreparedRecoveryGuard)
			set, manifestID, attempt, occurrence, artifactID := domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID()
			controlKey, _ := domain.PreparedControlKey(set)
			memberKey, _ := domain.PreparedMemberKey(set, 0)
			manifestKey, _ := domain.PreparedManifestKey(set)
			finalKey, _ := StorageKeyFor(artifactID)
			m := domain.PreparedManifestV1{Version: domain.PreparedManifestVersionV1, SetID: set, ManifestID: manifestID, ArtifactStoreID: g.identity.ArtifactStoreID, StoreIncarnationNonce: g.identity.IncarnationNonce, StoreBackendKind: g.identity.BackendKind, StoreMarkerFormat: g.identity.MarkerFormat, StoreMarkerVersion: g.identity.MarkerVersion, ProviderAttemptID: &attempt, ResultOccurrenceID: occurrence, Control: domain.PreparedObjectRefV1{StorageKey: controlKey, ContentSizeBytes: 2, ContentSHA256: DigestString(DigestBytes([]byte("{}")))}, Members: []domain.PreparedMemberV1{{Ordinal: 0, PublicationID: domain.NewID(), ArtifactID: artifactID, PreparedKey: memberKey, FinalKey: finalKey, Role: domain.ArtifactRoleSemanticResult, ContentType: "application/json", ArtifactType: "normalized-result", ContentSizeBytes: 2, ContentSHA256: DigestString(DigestBytes([]byte("{}")))}}}
			raw, err := m.CanonicalJSON()
			if err != nil {
				t.Fatal(err)
			}
			keys := []string{controlKey, memberKey, manifestKey}
			values := []string{"{}", "{}", string(raw)}
			for i, key := range keys {
				if _, err := writePreparedExclusive(g.rootFD, key, strings.NewReader(values[i]), int64(len(values[i])), DigestBytes([]byte(values[i])), 1<<20); err != nil {
					t.Fatal(err)
				}
			}
			for _, key := range keys[:stopped] {
				if err := unlinkPrepared(g.rootFD, key); err != nil {
					t.Fatal(err)
				}
			}
			size, digest, count := int64(len(raw)), DigestString(DigestBytes(raw)), 1
			record := domain.PreparedSetRecord{ID: set, ManifestID: manifestID, ArtifactStoreID: g.identity.ArtifactStoreID, StoreIncarnationNonce: g.identity.IncarnationNonce, State: domain.PreparedResolvedAdopted, ResultOccurrenceID: &occurrence, ManifestSHA256: &digest, ManifestSizeBytes: &size, MemberCount: &count}
			if _, err := g.DeleteResolvedPrepared(context.Background(), record); err != nil {
				t.Fatal(err)
			}
			if _, err := g.DeleteResolvedPrepared(context.Background(), record); err != nil {
				t.Fatal(err)
			}
			key, _ := domain.PreparedSetPrefix(set)
			if _, _, err := openStoreParent(g.rootFD, key+"/missing", false); !errors.Is(err, unix.ENOENT) {
				t.Fatal("cleanup left set directory")
			}
		})
	}
}

func TestNonadmissionCleanupBeforeAnyPreparedDirectoryExists(t *testing.T) {
	local, publisher := linuxGuard(t)
	publisher.Close()
	guard, err := local.AcquirePreparedRecovery(context.Background(), local.Identity())
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	occurrence, terminal := domain.NewID(), domain.NewID()
	record := domain.PreparedSetRecord{ID: domain.NewID(), ManifestID: domain.NewID(), ArtifactStoreID: local.identity.ArtifactStoreID, StoreIncarnationNonce: local.identity.IncarnationNonce, State: domain.PreparedResolvedAbandoned, ResultOccurrenceID: &occurrence, ProviderTerminalEventID: &terminal, NonadmissionDetails: []byte(`{"code":"result_contract_limit"}`)}
	for i := 0; i < 2; i++ {
		if _, err := guard.DeleteResolvedPrepared(context.Background(), record); err != nil {
			t.Fatal(err)
		}
	}
}
