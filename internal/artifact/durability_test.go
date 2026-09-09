package artifact

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/domain"
)

func TestDirectorySyncChainRunsChildToParent(t *testing.T) {
	root := t.TempDir()
	leaf := filepath.Join(root, "v1", "ab")
	if err := os.MkdirAll(leaf, 0700); err != nil {
		t.Fatal(err)
	}
	var calls []string
	err := syncDirectoryChainWith(leaf, root, func(path string) (directorySyncResult, error) {
		calls = append(calls, path)
		return directorySyncPerformed, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{leaf, filepath.Join(root, "v1"), root}
	if !slices.Equal(calls, want) {
		t.Fatalf("directory sync order=%q want=%q", calls, want)
	}
}

func TestDirectorySyncChainPropagatesSupportedFailure(t *testing.T) {
	root := t.TempDir()
	leaf := filepath.Join(root, "v1", "ab")
	if err := os.MkdirAll(leaf, 0700); err != nil {
		t.Fatal(err)
	}
	cause := errors.New("directory flush failed")
	err := syncDirectoryChainWith(leaf, root, func(path string) (directorySyncResult, error) {
		if path == filepath.Join(root, "v1") {
			return 0, cause
		}
		return directorySyncPerformed, nil
	})
	if !errors.Is(err, cause) {
		t.Fatalf("directory sync error=%v", err)
	}
}

func TestPlatformDirectorySyncOutcomeIsExplicit(t *testing.T) {
	result, err := platformSyncDirectory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		if result != directorySyncUnsupported {
			t.Fatalf("Windows directory sync result=%d want unsupported", result)
		}
		return
	}
	if result != directorySyncPerformed {
		t.Fatalf("directory sync result=%d want performed", result)
	}
}

func TestLocalPutDoesNotReportSuccessWhenDirectorySyncFails(t *testing.T) {
	_, store := initializedLocal(t)
	fixedID := domain.ID("323e4567-e89b-42d3-a456-426614174000")
	store.newID = func() domain.ID { return fixedID }
	cause := errors.New("directory flush failed")
	restoreDirectorySync(t, func(string) (directorySyncResult, error) { return 0, cause })

	if _, err := store.Put(context.Background(), completePutRequest()); !errors.Is(err, cause) {
		t.Fatalf("Put error=%v", err)
	}
	key, err := StorageKeyFor(fixedID)
	if err != nil {
		t.Fatal(err)
	}
	path, err := store.pathForKey(key, fixedID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("late durability failure removed create-exclusive publication: %v", err)
	}
}

func TestMarkerDirectorySyncFailurePreventsRegistration(t *testing.T) {
	root := t.TempDir()
	registry := newMemoryRegistry()
	storeID := domain.NewID()
	cause := errors.New("marker directory flush failed")
	restoreDirectorySync(t, func(string) (directorySyncResult, error) { return 0, cause })

	if _, err := InitializeLocal(context.Background(), root, storeID, registry, InitializationOptions{}); !errors.Is(err, cause) {
		t.Fatalf("InitializeLocal error=%v", err)
	}
	if _, err := registry.ArtifactStore(context.Background(), storeID); !errors.Is(err, ErrStoreRegistrationNotFound) {
		t.Fatalf("failed marker durability mutated registry: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, markerName)); err != nil {
		t.Fatalf("late marker durability failure removed marker: %v", err)
	}
}

func TestResumeRegistrationRetriesMarkerAndAncestorDurability(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "created-parent", "store")
	registry := newMemoryRegistry()
	storeID := domain.NewID()
	cause := errors.New("marker directory flush failed")
	restoreDirectorySync(t, func(string) (directorySyncResult, error) { return 0, cause })
	if _, err := InitializeLocal(context.Background(), root, storeID, registry, InitializationOptions{}); !errors.Is(err, cause) {
		t.Fatalf("initialization error=%v", err)
	}

	var calls []string
	restoreDirectorySync(t, func(path string) (directorySyncResult, error) {
		calls = append(calls, path)
		return directorySyncPerformed, nil
	})
	result, err := InitializeLocal(context.Background(), root, storeID, registry, InitializationOptions{ResumeRegistration: true})
	if err != nil || result.Status != "registration_resumed" {
		t.Fatalf("resume result=%#v error=%v", result, err)
	}
	top, err := filesystemRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for current := root; ; current = filepath.Dir(current) {
		want = append(want, current)
		if current == top {
			break
		}
	}
	if !slices.Equal(calls, want) {
		t.Fatalf("resume directory sync order=%q want=%q", calls, want)
	}
}

func TestNewArtifactRootSyncsEveryCreatedAncestorBeforeRegistration(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "created-parent", "store")
	registry := newMemoryRegistry()
	var calls []string
	restoreDirectorySync(t, func(path string) (directorySyncResult, error) {
		calls = append(calls, path)
		return directorySyncPerformed, nil
	})

	if _, err := InitializeLocal(context.Background(), root, domain.NewID(), registry, InitializationOptions{}); err != nil {
		t.Fatal(err)
	}
	want := []string{root, filepath.Join(base, "created-parent"), base}
	if !slices.Equal(calls, want) {
		t.Fatalf("new root sync order=%q want=%q", calls, want)
	}
}

func restoreDirectorySync(t *testing.T, replacement directorySyncFunc) {
	t.Helper()
	previous := syncDirectoryEntry
	syncDirectoryEntry = replacement
	t.Cleanup(func() { syncDirectoryEntry = previous })
}
