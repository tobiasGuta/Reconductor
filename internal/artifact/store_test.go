package artifact

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/domain"
)

type memoryRegistry struct {
	mu     sync.Mutex
	stores map[domain.ID]domain.ArtifactStore
}

func newMemoryRegistry() *memoryRegistry {
	return &memoryRegistry{stores: map[domain.ID]domain.ArtifactStore{}}
}

func (r *memoryRegistry) ArtifactStore(_ context.Context, id domain.ID) (domain.ArtifactStore, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	store, ok := r.stores[id]
	if !ok {
		return domain.ArtifactStore{}, ErrStoreRegistrationNotFound
	}
	return store, nil
}

func (r *memoryRegistry) RegisterArtifactStore(_ context.Context, registration domain.ArtifactStoreRegistration) (domain.ArtifactStore, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.stores[registration.ID]; ok {
		if err := registrationsMatch(existing, registration); err != nil {
			return domain.ArtifactStore{}, err
		}
		return existing, nil
	}
	for _, existing := range r.stores {
		if existing.IncarnationNonce == registration.IncarnationNonce {
			return domain.ArtifactStore{}, errors.New("incarnation nonce conflict")
		}
	}
	store := domain.ArtifactStore{ArtifactStoreRegistration: registration, CreatedAt: time.Now().UTC()}
	r.stores[registration.ID] = store
	return store, nil
}

func TestStorageKeyV1Canonical(t *testing.T) {
	id := domain.ID("123e4567-e89b-42d3-a456-426614174000")
	key, err := StorageKeyFor(id)
	if err != nil || key != "v1/12/123e4567-e89b-42d3-a456-426614174000" {
		t.Fatalf("key=%q err=%v", key, err)
	}
	for _, invalid := range []string{
		"/v1/12/123e4567-e89b-42d3-a456-426614174000",
		`v1\12\123e4567-e89b-42d3-a456-426614174000`,
		"v1/12/123E4567-e89b-42d3-a456-426614174000",
		"v1/13/123e4567-e89b-42d3-a456-426614174000",
		"v1/12/../123e4567-e89b-42d3-a456-426614174000",
		"C:/v1/12/123e4567-e89b-42d3-a456-426614174000",
		"v1/12/123e4567-e89b-42d3-a456-426614174000.json",
		"v1/12/123e4567-e89b-42d3-a456-42661417400%30",
		"v1/12/123e4567-e89b-42d3-a456-42661417400é",
	} {
		if err := ValidateStorageKey(invalid, id); err == nil {
			t.Fatalf("invalid key accepted: %q", invalid)
		}
	}
}

func TestInitializeLocalStateMachine(t *testing.T) {
	ctx := context.Background()
	storeID := domain.NewID()
	registry := newMemoryRegistry()
	root := filepath.Join(t.TempDir(), "missing")
	first, err := InitializeLocal(ctx, root, storeID, registry, InitializationOptions{})
	if err != nil || first.Status != "initialized" {
		t.Fatalf("first=%#v err=%v", first, err)
	}
	second, err := InitializeLocal(ctx, root, storeID, registry, InitializationOptions{})
	if err != nil || second.Status != "already_initialized" || !second.Store.CreatedAt.Equal(first.Store.CreatedAt) {
		t.Fatalf("second=%#v err=%v", second, err)
	}
}

func TestConcurrentInitializeNeverOverwritesMarker(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "concurrent")
	storeID := domain.NewID()
	registry := newMemoryRegistry()
	start := make(chan struct{})
	errorsByAttempt := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := InitializeLocal(ctx, root, storeID, registry, InitializationOptions{})
			errorsByAttempt <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errorsByAttempt)
	successes := 0
	for err := range errorsByAttempt {
		if err == nil {
			successes++
		}
	}
	if successes < 1 {
		t.Fatal("no concurrent initializer succeeded")
	}
	marker, err := readMarker(filepath.Join(root, markerName))
	if err != nil {
		t.Fatal(err)
	}
	registered, err := registry.ArtifactStore(ctx, storeID)
	if err != nil {
		t.Fatal(err)
	}
	if err := registrationsMatch(registered, marker); err != nil {
		t.Fatalf("published marker was not the registered winner: %v", err)
	}
}

func TestInitializeLocalRequiresExplicitResume(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	storeID := domain.NewID()
	registration := domain.ArtifactStoreRegistration{ID: storeID, IncarnationNonce: domain.NewID(), BackendKind: BackendKind, MarkerFormat: MarkerFormat, MarkerVersion: MarkerVersion}
	if err := writeMarker(filepath.Join(root, markerName), registration); err != nil {
		t.Fatal(err)
	}
	registry := newMemoryRegistry()
	if _, err := InitializeLocal(ctx, root, storeID, registry, InitializationOptions{}); err == nil {
		t.Fatal("marker without registration resumed implicitly")
	}
	result, err := InitializeLocal(ctx, root, storeID, registry, InitializationOptions{ResumeRegistration: true})
	if err != nil || result.Status != "registration_resumed" || result.Store.IncarnationNonce != registration.IncarnationNonce {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestInitializeLocalRejectsRegistrationWithoutMarker(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	storeID := domain.NewID()
	registry := newMemoryRegistry()
	if _, err := registry.RegisterArtifactStore(ctx, domain.ArtifactStoreRegistration{ID: storeID, IncarnationNonce: domain.NewID(), BackendKind: BackendKind, MarkerFormat: MarkerFormat, MarkerVersion: MarkerVersion}); err != nil {
		t.Fatal(err)
	}
	if _, err := InitializeLocal(ctx, root, storeID, registry, InitializationOptions{}); err == nil {
		t.Fatal("registration without marker accepted")
	}
}

func TestInitializeLocalNonemptyAndReservedBehavior(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "legacy.bin"), []byte("legacy"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := InitializeLocal(ctx, root, domain.NewID(), newMemoryRegistry(), InitializationOptions{}); err == nil {
		t.Fatal("nonempty root accepted without acknowledgement")
	}
	if _, err := InitializeLocal(ctx, root, domain.NewID(), newMemoryRegistry(), InitializationOptions{AllowNonemptyRoot: true}); err != nil {
		t.Fatalf("acknowledged legacy root rejected: %v", err)
	}
	reserved := t.TempDir()
	if err := os.Mkdir(filepath.Join(reserved, "v1"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := InitializeLocal(ctx, reserved, domain.NewID(), newMemoryRegistry(), InitializationOptions{AllowNonemptyRoot: true}); err == nil {
		t.Fatal("reserved v1 subtree accepted")
	}
}

func TestMarkerParsingIsStrict(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, markerName)
	storeID, nonce := domain.NewID(), domain.NewID()
	valid := `{"marker_format":"reconductor-artifact-store","marker_version":1,"backend_kind":"local-v1","store_id":"` + string(storeID) + `","incarnation_nonce":"` + string(nonce) + `"}`
	for name, content := range map[string]string{
		"unknown":   strings.TrimSuffix(valid, "}") + `,"extra":true}`,
		"duplicate": strings.TrimSuffix(valid, "}") + `,"store_id":"` + string(storeID) + `"}`,
		"missing":   strings.Replace(valid, `"backend_kind":"local-v1",`, "", 1),
		"trailing":  valid + `{}`,
		"type":      strings.Replace(valid, `"marker_version":1`, `"marker_version":"1"`, 1),
		"uppercase": strings.Replace(valid, string(storeID), strings.ToUpper(string(storeID)), 1),
		"oversized": valid + strings.Repeat(" ", maximumMarkerLen),
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := readMarker(path); err == nil {
				t.Fatal("invalid marker accepted")
			}
		})
	}
}

func TestOpenLocalIsValidateOnlyAndRootCanMove(t *testing.T) {
	ctx := context.Background()
	parent := t.TempDir()
	root := filepath.Join(parent, "first")
	storeID := domain.NewID()
	registry := newMemoryRegistry()
	if _, err := OpenLocal(ctx, root, storeID, registry, nil); err == nil {
		t.Fatal("OpenLocal initialized a missing root")
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("OpenLocal mutated missing root: %v", err)
	}
	if _, err := InitializeLocal(ctx, root, storeID, registry, InitializationOptions{}); err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(parent, "moved")
	if err := os.Rename(root, moved); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenLocal(ctx, moved, storeID, registry, nil); err != nil {
		t.Fatalf("moved store failed validation: %v", err)
	}
}

func TestOpenLocalRejectsEveryStoreIdentityMismatch(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	storeID := domain.NewID()
	registry := newMemoryRegistry()
	result, err := InitializeLocal(ctx, root, storeID, registry, InitializationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	markerPath := filepath.Join(root, markerName)
	validMarker, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	for name, marker := range map[string][]byte{
		"store ID":       []byte(strings.Replace(string(validMarker), string(storeID), string(domain.NewID()), 1)),
		"backend kind":   []byte(strings.Replace(string(validMarker), BackendKind, "local-v2", 1)),
		"marker format":  []byte(strings.Replace(string(validMarker), MarkerFormat, "other-format", 1)),
		"marker version": []byte(strings.Replace(string(validMarker), `"marker_version":1`, `"marker_version":2`, 1)),
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(markerPath, marker, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := InitializeLocal(ctx, root, storeID, registry, InitializationOptions{ResumeRegistration: true, AllowNonemptyRoot: true}); err == nil {
				t.Fatal("mismatched marker accepted during initialization")
			}
			unchanged, err := os.ReadFile(markerPath)
			if err != nil || !bytes.Equal(unchanged, marker) {
				t.Fatalf("failed initialization rewrote marker: changed=%v error=%v", !bytes.Equal(unchanged, marker), err)
			}
			if _, err := OpenLocal(ctx, root, storeID, registry, nil); err == nil {
				t.Fatal("mismatched marker accepted")
			}
		})
	}
	if err := os.WriteFile(markerPath, validMarker, 0600); err != nil {
		t.Fatal(err)
	}
	registry.mu.Lock()
	changed := registry.stores[storeID]
	changed.IncarnationNonce = domain.NewID()
	registry.stores[storeID] = changed
	registry.mu.Unlock()
	if _, err := InitializeLocal(ctx, root, storeID, registry, InitializationOptions{ResumeRegistration: true}); err == nil {
		t.Fatal("registry nonce mismatch accepted during initialization")
	}
	if _, err := OpenLocal(ctx, root, storeID, registry, nil); err == nil {
		t.Fatal("registry nonce mismatch accepted")
	}
	if result.Store.ID != storeID {
		t.Fatalf("initialized StoreID=%s", result.Store.ID)
	}
}

func TestOpenLocalRejectsSymlinkMarkerWhereSupported(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "marker-target.json")
	storeID, nonce := domain.NewID(), domain.NewID()
	registration := domain.ArtifactStoreRegistration{ID: storeID, IncarnationNonce: nonce, BackendKind: BackendKind, MarkerFormat: MarkerFormat, MarkerVersion: MarkerVersion}
	if err := writeMarker(target, registration); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, markerName)); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	registry := newMemoryRegistry()
	if _, err := registry.RegisterArtifactStore(context.Background(), registration); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenLocal(context.Background(), root, storeID, registry, nil); err == nil {
		t.Fatal("symlink marker accepted")
	}
}

func TestNativeAndDockerPhysicalStoresRemainIsolated(t *testing.T) {
	ctx := context.Background()
	registry := newMemoryRegistry()
	nativeRoot, dockerRoot := filepath.Join(t.TempDir(), "native"), filepath.Join(t.TempDir(), "docker")
	nativeID, dockerID := domain.NewID(), domain.NewID()
	if _, err := InitializeLocal(ctx, nativeRoot, nativeID, registry, InitializationOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := InitializeLocal(ctx, dockerRoot, dockerID, registry, InitializationOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenLocal(ctx, nativeRoot, dockerID, registry, nil); err == nil {
		t.Fatal("Docker StoreID opened the native physical store")
	}
	if _, err := OpenLocal(ctx, dockerRoot, nativeID, registry, nil); err == nil {
		t.Fatal("native StoreID opened the Docker physical store")
	}
}

func TestAcknowledgedForeignLegacyFilesDoNotBlockModernPut(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	for index := 0; index < 38; index++ {
		name := fmt.Sprintf("foreign-legacy-%02d.bin", index)
		if err := os.WriteFile(filepath.Join(root, name), []byte("unread fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	registry := newMemoryRegistry()
	storeID := domain.NewID()
	if _, err := InitializeLocal(ctx, root, storeID, registry, InitializationOptions{AllowNonemptyRoot: true}); err != nil {
		t.Fatal(err)
	}
	store, err := OpenLocal(ctx, root, storeID, registry, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(ctx, completePutRequest()); err != nil {
		t.Fatalf("modern Put was blocked by foreign legacy fixtures: %v", err)
	}
}
