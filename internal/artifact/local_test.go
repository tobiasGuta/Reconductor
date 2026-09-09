package artifact

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/redaction"
)

func TestLocalArtifactLineageDigestAndRedaction(t *testing.T) {
	root, store := initializedLocal(t)
	req := PutRequest{ProgramID: domain.NewID(), TaskID: domain.NewID(), WorkflowRunID: domain.NewID(), StepRunID: domain.NewID(), ToolRunID: domain.NewID(), Type: "log", ContentType: "text/plain", Name: "tool.log", Data: []byte("Authorization: Bearer secret-value")}
	a, err := store.Put(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if a.Size == 0 || len(a.SHA256) != 64 || a.RedactionState != "redacted" {
		t.Fatalf("bad metadata: %#v", a)
	}
	if a.AddressingVersion != 1 || a.ArtifactStoreID == nil || a.StorageKey == nil || a.StorageLocation != nil {
		t.Fatalf("bad modern address: %#v", a)
	}
	location, err := store.pathForKey(*a.StorageKey, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(location, root) || strings.Contains(*a.StorageKey, req.Name) {
		t.Fatalf("unexpected address key=%q path=%q", *a.StorageKey, location)
	}
	b, err := os.ReadFile(location)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "secret-value") {
		t.Fatal("artifact leaked secret")
	}
}
func TestLocalArtifactRequiresLineage(t *testing.T) {
	_, store := initializedLocal(t)
	if _, err := store.Put(context.Background(), PutRequest{Name: "x"}); err == nil {
		t.Fatal("missing lineage accepted")
	}
	request := completePutRequest()
	request.ProgramID = "not-a-canonical-id"
	if _, err := store.Put(context.Background(), request); err == nil {
		t.Fatal("noncanonical ProgramID accepted")
	}
}

func TestLocalArtifactRequiresValidatedInitialization(t *testing.T) {
	if _, err := (&Local{}).Put(context.Background(), completePutRequest()); err == nil {
		t.Fatal("zero-value Local accepted Put")
	}
}

func TestLocalPutAppliesExpiryAndSensitiveMetadata(t *testing.T) {
	_, store := initializedLocal(t)
	request := completePutRequest()
	request.Sensitive = true
	request.Retention = time.Hour
	request.Data = []byte("sensitive")
	artifact, err := store.Put(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if artifact.ExpiresAt == nil || artifact.RedactionState != "sensitive-unredacted" || !artifact.Sensitive {
		t.Fatalf("metadata=%#v", artifact)
	}
	if strings.Contains(*artifact.StorageKey, "sensitive") {
		t.Fatalf("sensitivity leaked into key %q", *artifact.StorageKey)
	}
}

func TestLocalPutNeverOverwritesExistingUUIDPath(t *testing.T) {
	_, store := initializedLocal(t)
	fixed := domain.ID("123e4567-e89b-42d3-a456-426614174000")
	store.newID = func() domain.ID { return fixed }
	request := completePutRequest()
	request.Data = []byte("winner")
	first, err := store.Put(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	request.Data = []byte("loser")
	if _, err := store.Put(context.Background(), request); err == nil {
		t.Fatal("existing artifact was overwritten")
	}
	location, _ := store.pathForKey(*first.StorageKey, first.ID)
	data, err := os.ReadFile(location)
	if err != nil || string(data) != "winner" {
		t.Fatalf("winner bytes=%q err=%v", data, err)
	}
}

func TestConcurrentSameUUIDPublicationHasOneWinner(t *testing.T) {
	_, store := initializedLocal(t)
	fixed := domain.ID("223e4567-e89b-42d3-a456-426614174000")
	store.newID = func() domain.ID { return fixed }
	request := completePutRequest()
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := store.Put(context.Background(), request)
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successful writers=%d want=1", successes)
	}
}

func TestPublishedArtifactRemainsOrphanedWhenPersistenceFails(t *testing.T) {
	_, store := initializedLocal(t)
	published, err := store.Put(context.Background(), completePutRequest())
	if err != nil {
		t.Fatal(err)
	}
	location, err := store.pathForKey(*published.StorageKey, published.ID)
	if err != nil {
		t.Fatal(err)
	}
	persist := func(domain.Artifact) error { return errors.New("simulated database failure") }
	if err := persist(published); err == nil {
		t.Fatal("simulated persistence unexpectedly succeeded")
	}
	if _, err := os.Stat(location); err != nil {
		t.Fatalf("published orphan was cleaned up: %v", err)
	}
}

func initializedLocal(t *testing.T) (string, *Local) {
	t.Helper()
	root := t.TempDir()
	registry := newMemoryRegistry()
	storeID := domain.NewID()
	if _, err := InitializeLocal(context.Background(), root, storeID, registry, InitializationOptions{}); err != nil {
		t.Fatal(err)
	}
	store, err := OpenLocal(context.Background(), root, storeID, registry, redaction.New())
	if err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}
	return abs, store
}

func completePutRequest() PutRequest {
	return PutRequest{ProgramID: domain.NewID(), TaskID: domain.NewID(), WorkflowRunID: domain.NewID(), StepRunID: domain.NewID(), ToolRunID: domain.NewID(), Type: "log", ContentType: "text/plain", Name: "ignored.log", Data: []byte("ok")}
}
