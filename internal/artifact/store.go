package artifact

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/redaction"
)

const (
	BackendKind      = "local-v1"
	MarkerFormat     = "reconductor-artifact-store"
	MarkerVersion    = 1
	markerName       = ".reconductor-artifact-store.json"
	maximumMarkerLen = 1024
)

var ErrStoreRegistrationNotFound = errors.New("artifact store registration not found")

type StoreRegistry interface {
	ArtifactStore(context.Context, domain.ID) (domain.ArtifactStore, error)
	RegisterArtifactStore(context.Context, domain.ArtifactStoreRegistration) (domain.ArtifactStore, error)
}

type InitializationOptions struct {
	AllowNonemptyRoot  bool
	ResumeRegistration bool
}

type InitializationResult struct {
	Store  domain.ArtifactStore `json:"store"`
	Status string               `json:"status"`
}

type markerDocument struct {
	MarkerFormat     string `json:"marker_format"`
	MarkerVersion    int    `json:"marker_version"`
	BackendKind      string `json:"backend_kind"`
	StoreID          string `json:"store_id"`
	IncarnationNonce string `json:"incarnation_nonce"`
}

func StorageKeyFor(id domain.ID) (string, error) {
	value := string(id)
	if _, err := domain.ParseID(value); err != nil {
		return "", fmt.Errorf("artifact identity is not canonical")
	}
	return "v1/" + value[:2] + "/" + value, nil
}

func ValidateStorageKey(key string, id domain.ID) error {
	want, err := StorageKeyFor(id)
	if err != nil {
		return err
	}
	if key != want {
		return fmt.Errorf("artifact storage key is not canonical for its identity")
	}
	return nil
}

func InitializeLocal(ctx context.Context, root string, expectedStoreID domain.ID, registry StoreRegistry, options InitializationOptions) (InitializationResult, error) {
	if registry == nil {
		return InitializationResult{}, fmt.Errorf("artifact store registry is required")
	}
	if strings.TrimSpace(root) == "" {
		return InitializationResult{}, fmt.Errorf("artifact root is required")
	}
	storeID, err := domain.ParseID(string(expectedStoreID))
	if err != nil {
		return InitializationResult{}, fmt.Errorf("configured artifact store ID is not canonical")
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return InitializationResult{}, fmt.Errorf("resolve artifact root: %w", err)
	}
	var createdRootAncestor string
	info, err := os.Stat(absRoot)
	if errors.Is(err, os.ErrNotExist) {
		createdRootAncestor, err = nearestExistingDirectory(absRoot)
		if err != nil {
			return InitializationResult{}, fmt.Errorf("find existing artifact root ancestor: %w", err)
		}
		if err := os.MkdirAll(absRoot, 0700); err != nil {
			return InitializationResult{}, fmt.Errorf("create artifact root: %w", err)
		}
		info, err = os.Stat(absRoot)
	}
	if err != nil {
		return InitializationResult{}, fmt.Errorf("access artifact root: %w", err)
	}
	if !info.IsDir() {
		return InitializationResult{}, fmt.Errorf("artifact root is not a directory")
	}

	markerPath := filepath.Join(absRoot, markerName)
	markerInfo, markerErr := os.Lstat(markerPath)
	switch {
	case markerErr == nil:
		if !markerInfo.Mode().IsRegular() || markerInfo.Mode()&os.ModeSymlink != 0 {
			return InitializationResult{}, fmt.Errorf("artifact store marker is not a regular file")
		}
		registration, err := readMarker(markerPath)
		if err != nil {
			return InitializationResult{}, err
		}
		if err := validateRegistration(registration, storeID); err != nil {
			return InitializationResult{}, err
		}
		registered, err := registry.ArtifactStore(ctx, storeID)
		if err == nil {
			if err := registrationsMatch(registered, registration); err != nil {
				return InitializationResult{}, err
			}
			return InitializationResult{Store: registered, Status: "already_initialized"}, nil
		}
		if !isRegistrationMissing(err) {
			return InitializationResult{}, fmt.Errorf("load artifact store registration: %w", err)
		}
		if !options.ResumeRegistration {
			return InitializationResult{}, fmt.Errorf("artifact store marker exists without registration; explicit resume is required")
		}
		if err := syncMarkerForRegistration(markerPath, absRoot); err != nil {
			return InitializationResult{}, err
		}
		registered, err = registry.RegisterArtifactStore(ctx, registration)
		if err != nil {
			return InitializationResult{}, fmt.Errorf("resume artifact store registration: %w", err)
		}
		return InitializationResult{Store: registered, Status: "registration_resumed"}, nil
	case !errors.Is(markerErr, os.ErrNotExist):
		return InitializationResult{}, fmt.Errorf("inspect artifact store marker: %w", markerErr)
	}

	if _, err := registry.ArtifactStore(ctx, storeID); err == nil {
		return InitializationResult{}, fmt.Errorf("artifact store registration exists without marker")
	} else if !isRegistrationMissing(err) {
		return InitializationResult{}, fmt.Errorf("load artifact store registration: %w", err)
	}
	if _, err := os.Lstat(filepath.Join(absRoot, "v1")); err == nil {
		return InitializationResult{}, fmt.Errorf("unmarked artifact root contains reserved modern v1 subtree")
	} else if !errors.Is(err, os.ErrNotExist) {
		return InitializationResult{}, fmt.Errorf("inspect reserved artifact subtree: %w", err)
	}
	entries, err := os.ReadDir(absRoot)
	if err != nil {
		return InitializationResult{}, fmt.Errorf("read artifact root: %w", err)
	}
	if len(entries) > 0 && !options.AllowNonemptyRoot {
		return InitializationResult{}, fmt.Errorf("unmarked artifact root is not empty; explicit acknowledgement is required")
	}
	registration := domain.ArtifactStoreRegistration{ID: storeID, IncarnationNonce: domain.NewID(), BackendKind: BackendKind, MarkerFormat: MarkerFormat, MarkerVersion: MarkerVersion}
	if err := writeMarker(markerPath, registration); err != nil {
		return InitializationResult{}, err
	}
	if createdRootAncestor != "" && filepath.Clean(createdRootAncestor) != filepath.Clean(absRoot) {
		if err := syncDirectoryChain(filepath.Dir(absRoot), createdRootAncestor); err != nil {
			return InitializationResult{}, fmt.Errorf("durably publish artifact root: %w", err)
		}
	}
	registered, err := registry.RegisterArtifactStore(ctx, registration)
	if err != nil {
		return InitializationResult{}, fmt.Errorf("register artifact store: %w", err)
	}
	return InitializationResult{Store: registered, Status: "initialized"}, nil
}

func OpenLocal(ctx context.Context, root string, expectedStoreID domain.ID, registry StoreRegistry, r *redaction.Redactor) (*Local, error) {
	if registry == nil {
		return nil, fmt.Errorf("artifact store registry is required")
	}
	if strings.TrimSpace(root) == "" {
		return nil, fmt.Errorf("artifact root is required")
	}
	storeID, err := domain.ParseID(string(expectedStoreID))
	if err != nil {
		return nil, fmt.Errorf("configured artifact store ID is not canonical")
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve artifact root: %w", err)
	}
	info, err := os.Stat(absRoot)
	if err != nil {
		return nil, fmt.Errorf("access artifact root: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("artifact root is not a directory")
	}
	markerPath := filepath.Join(absRoot, markerName)
	markerInfo, err := os.Lstat(markerPath)
	if err != nil {
		return nil, fmt.Errorf("artifact store marker is unavailable: %w", err)
	}
	if !markerInfo.Mode().IsRegular() || markerInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("artifact store marker is not a regular file")
	}
	registration, err := readMarker(markerPath)
	if err != nil {
		return nil, err
	}
	if err := validateRegistration(registration, storeID); err != nil {
		return nil, err
	}
	registered, err := registry.ArtifactStore(ctx, storeID)
	if err != nil {
		return nil, fmt.Errorf("load artifact store registration: %w", err)
	}
	if err := registrationsMatch(registered, registration); err != nil {
		return nil, err
	}
	if r == nil {
		r = redaction.New()
	}
	return &Local{root: absRoot, storeID: storeID, identity: StoreIdentityFrom(registered), redactor: r, newID: domain.NewID, initialized: true, rootInfo: info, markerInfo: markerInfo}, nil
}

func validateRegistration(registration domain.ArtifactStoreRegistration, expectedStoreID domain.ID) error {
	if registration.ID != expectedStoreID {
		return fmt.Errorf("artifact store marker ID does not match configured store")
	}
	if _, err := domain.ParseID(string(registration.IncarnationNonce)); err != nil {
		return fmt.Errorf("artifact store marker nonce is not canonical")
	}
	if registration.BackendKind != BackendKind || registration.MarkerFormat != MarkerFormat || registration.MarkerVersion != MarkerVersion {
		return fmt.Errorf("artifact store marker format is unsupported")
	}
	return nil
}

func registrationsMatch(store domain.ArtifactStore, registration domain.ArtifactStoreRegistration) error {
	if store.ID != registration.ID || store.IncarnationNonce != registration.IncarnationNonce || store.BackendKind != registration.BackendKind || store.MarkerFormat != registration.MarkerFormat || store.MarkerVersion != registration.MarkerVersion {
		return fmt.Errorf("artifact store marker and registration do not match")
	}
	return nil
}

func isRegistrationMissing(err error) bool {
	return errors.Is(err, ErrStoreRegistrationNotFound)
}

func writeMarker(path string, registration domain.ArtifactStoreRegistration) error {
	document := markerDocument{MarkerFormat: registration.MarkerFormat, MarkerVersion: registration.MarkerVersion, BackendKind: registration.BackendKind, StoreID: string(registration.ID), IncarnationNonce: string(registration.IncarnationNonce)}
	data, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("encode artifact store marker: %w", err)
	}
	data = append(data, '\n')
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create artifact store marker exclusively: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("write artifact store marker: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync artifact store marker: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close artifact store marker: %w", err)
	}
	if err := syncDirectoryChain(filepath.Dir(path), filepath.Dir(path)); err != nil {
		return fmt.Errorf("durably publish artifact store marker: %w", err)
	}
	return nil
}

func syncMarkerForRegistration(path, root string) error {
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open artifact store marker for durability retry: %w", err)
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	if syncErr != nil || closeErr != nil {
		return fmt.Errorf("sync artifact store marker for registration: %w", errors.Join(syncErr, closeErr))
	}
	top, err := filesystemRoot(root)
	if err != nil {
		return fmt.Errorf("resolve artifact store durability root: %w", err)
	}
	if err := syncDirectoryChain(root, top); err != nil {
		return fmt.Errorf("durably republish artifact store marker: %w", err)
	}
	return nil
}

func readMarker(path string) (domain.ArtifactStoreRegistration, error) {
	file, err := os.Open(path)
	if err != nil {
		return domain.ArtifactStoreRegistration{}, fmt.Errorf("open artifact store marker: %w", err)
	}
	defer file.Close()
	return readMarkerFrom(file)
}

func readMarkerFrom(reader io.Reader) (domain.ArtifactStoreRegistration, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maximumMarkerLen+1))
	if err != nil {
		return domain.ArtifactStoreRegistration{}, fmt.Errorf("read artifact store marker: %w", err)
	}
	if len(data) > maximumMarkerLen {
		return domain.ArtifactStoreRegistration{}, fmt.Errorf("artifact store marker is oversized")
	}
	fields, err := decodeMarkerFields(data)
	if err != nil {
		return domain.ArtifactStoreRegistration{}, err
	}
	if len(fields) != 5 {
		return domain.ArtifactStoreRegistration{}, fmt.Errorf("artifact store marker fields are incomplete")
	}
	var document markerDocument
	for name, target := range map[string]any{"marker_format": &document.MarkerFormat, "marker_version": &document.MarkerVersion, "backend_kind": &document.BackendKind, "store_id": &document.StoreID, "incarnation_nonce": &document.IncarnationNonce} {
		raw, ok := fields[name]
		if !ok {
			return domain.ArtifactStoreRegistration{}, fmt.Errorf("artifact store marker field %s is missing", name)
		}
		if err := json.Unmarshal(raw, target); err != nil {
			return domain.ArtifactStoreRegistration{}, fmt.Errorf("artifact store marker field %s has an invalid type", name)
		}
	}
	storeID, err := domain.ParseID(document.StoreID)
	if err != nil {
		return domain.ArtifactStoreRegistration{}, fmt.Errorf("artifact store marker ID is not canonical")
	}
	nonce, err := domain.ParseID(document.IncarnationNonce)
	if err != nil {
		return domain.ArtifactStoreRegistration{}, fmt.Errorf("artifact store marker nonce is not canonical")
	}
	return domain.ArtifactStoreRegistration{ID: storeID, IncarnationNonce: nonce, BackendKind: document.BackendKind, MarkerFormat: document.MarkerFormat, MarkerVersion: document.MarkerVersion}, nil
}

func decodeMarkerFields(data []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return nil, fmt.Errorf("artifact store marker must be one JSON object")
	}
	fields := map[string]json.RawMessage{}
	allowed := map[string]struct{}{"marker_format": {}, "marker_version": {}, "backend_kind": {}, "store_id": {}, "incarnation_nonce": {}}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, fmt.Errorf("decode artifact store marker: %w", err)
		}
		name, ok := token.(string)
		if !ok {
			return nil, fmt.Errorf("artifact store marker contains a non-string field name")
		}
		if _, ok := allowed[name]; !ok {
			return nil, fmt.Errorf("artifact store marker contains unknown field %s", name)
		}
		if _, duplicate := fields[name]; duplicate {
			return nil, fmt.Errorf("artifact store marker contains duplicate field %s", name)
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return nil, fmt.Errorf("decode artifact store marker field %s: %w", name, err)
		}
		fields[name] = raw
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return nil, fmt.Errorf("artifact store marker object is incomplete")
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) || token != nil {
		return nil, fmt.Errorf("artifact store marker contains trailing JSON")
	}
	return fields, nil
}
