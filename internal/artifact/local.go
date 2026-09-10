package artifact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/redaction"
)

type PutRequest struct {
	ProgramID, TaskID, WorkflowRunID, StepRunID, ToolRunID domain.ID
	Type, ContentType, Name                                string
	Sensitive                                              bool
	Retention                                              time.Duration
	Data                                                   []byte
}
type Storage interface {
	Put(context.Context, PutRequest) (domain.Artifact, error)
}
type Local struct {
	root        string
	storeID     domain.ID
	redactor    *redaction.Redactor
	newID       func() domain.ID
	initialized bool
}

func (l *Local) Put(_ context.Context, request PutRequest) (domain.Artifact, error) {
	if l == nil || !l.initialized || l.root == "" || l.storeID == "" || l.redactor == nil || l.newID == nil {
		return domain.Artifact{}, fmt.Errorf("artifact store is not initialized")
	}
	if request.ProgramID == "" || request.TaskID == "" || request.WorkflowRunID == "" || request.StepRunID == "" || request.ToolRunID == "" {
		return domain.Artifact{}, fmt.Errorf("complete artifact lineage is required")
	}
	for _, identity := range []struct {
		name string
		id   domain.ID
	}{{"ProgramID", request.ProgramID}, {"TaskID", request.TaskID}, {"WorkflowRunID", request.WorkflowRunID}, {"StepRunID", request.StepRunID}, {"ToolRunID", request.ToolRunID}} {
		if _, err := domain.ParseID(string(identity.id)); err != nil {
			return domain.Artifact{}, fmt.Errorf("artifact %s is not canonical", identity.name)
		}
	}
	data := request.Data
	state := "sensitive-unredacted"
	if !request.Sensitive {
		data = []byte(l.redactor.Text(string(data)))
		state = "redacted"
	}
	id := l.newID()
	key, err := StorageKeyFor(id)
	if err != nil {
		return domain.Artifact{}, err
	}
	location, err := l.pathForKey(key, id)
	if err != nil {
		return domain.Artifact{}, err
	}
	if err := os.MkdirAll(filepath.Dir(location), 0700); err != nil {
		return domain.Artifact{}, fmt.Errorf("create artifact key directory: %w", err)
	}
	file, err := os.OpenFile(location, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return domain.Artifact{}, fmt.Errorf("publish artifact without overwrite: %w", err)
	}
	written, writeErr := io.Copy(file, bytes.NewReader(data))
	if writeErr != nil || written != int64(len(data)) {
		_ = file.Close()
		if writeErr == nil {
			writeErr = io.ErrShortWrite
		}
		return domain.Artifact{}, fmt.Errorf("write artifact content: %w", writeErr)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return domain.Artifact{}, fmt.Errorf("sync artifact content: %w", err)
	}
	if err := file.Close(); err != nil {
		return domain.Artifact{}, fmt.Errorf("close artifact content: %w", err)
	}
	if err := syncDirectoryChain(filepath.Dir(location), l.root); err != nil {
		return domain.Artifact{}, fmt.Errorf("durably publish artifact path: %w", err)
	}
	sum := sha256.Sum256(data)
	created := time.Now().UTC()
	var expires *time.Time
	if request.Retention > 0 {
		value := created.Add(request.Retention)
		expires = &value
	}
	storeID := l.storeID
	storageKey := key
	return domain.Artifact{
		ID:                id,
		TaskID:            request.TaskID,
		WorkflowRunID:     request.WorkflowRunID,
		StepRunID:         request.StepRunID,
		ToolRunID:         request.ToolRunID,
		Type:              request.Type,
		ContentType:       request.ContentType,
		Size:              int64(len(data)),
		SHA256:            hex.EncodeToString(sum[:]),
		AddressingVersion: 1,
		ArtifactStoreID:   &storeID,
		StorageKey:        &storageKey,
		CreatedAt:         created,
		ExpiresAt:         expires,
		RedactionState:    state,
		Sensitive:         request.Sensitive,
	}, nil
}

func (l *Local) StoreID() domain.ID {
	if l == nil {
		return ""
	}
	return l.storeID
}

func (l *Local) DeleteContent(ctx context.Context, id domain.ID, storageKey string) (ContentDeletionOutcome, error) {
	if l == nil || !l.initialized || l.root == "" || l.storeID == "" {
		return "", fmt.Errorf("artifact store is not initialized")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if _, err := domain.ParseID(string(id)); err != nil {
		return "", fmt.Errorf("artifact ID is not canonical: %w", err)
	}
	if err := ValidateStorageKey(storageKey, id); err != nil {
		return "", fmt.Errorf("artifact storage key is not canonical for its identity: %w", err)
	}

	location, err := l.pathForKey(storageKey, id)
	if err != nil {
		return "", err
	}

	info, err := os.Lstat(location)
	switch {
	case err == nil:
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("%w: entry at %s is not a regular file", ErrUnexpectedEntryType, storageKey)
		}
		if err := os.Remove(location); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return l.syncExistingAncestorForAbsent(filepath.Dir(location))
			}
			return "", fmt.Errorf("remove artifact file: %w", err)
		}
		if err := syncDirectoryChain(filepath.Dir(location), l.root); err != nil {
			return "", &DurabilitySyncError{Err: fmt.Errorf("sync directory chain after delete: %w", err)}
		}
		return ContentRemoved, nil

	case errors.Is(err, os.ErrNotExist):
		return l.syncExistingAncestorForAbsent(filepath.Dir(location))

	default:
		return "", fmt.Errorf("inspect artifact file: %w", err)
	}
}

func (l *Local) syncExistingAncestorForAbsent(shardDir string) (ContentDeletionOutcome, error) {
	ancestor, err := nearestExistingAncestorLstat(shardDir, l.root)
	if err != nil {
		return "", err
	}
	if err := syncDirectoryChain(ancestor, l.root); err != nil {
		return "", &DurabilitySyncError{Err: fmt.Errorf("sync directory chain for absent artifact: %w", err)}
	}
	return ContentAlreadyAbsent, nil
}

func nearestExistingAncestorLstat(path, root string) (string, error) {
	current, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	for {
		if !within(absRoot, current) && filepath.Clean(current) != filepath.Clean(absRoot) {
			return "", fmt.Errorf("ancestor search left storage root")
		}
		info, statErr := os.Lstat(current)
		switch {
		case statErr == nil:
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return "", fmt.Errorf("%w: ancestor %s is not a regular directory", ErrUnexpectedEntryType, current)
			}
			return current, nil
		case !errors.Is(statErr, os.ErrNotExist):
			return "", statErr
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("no existing directory ancestor within root")
		}
		current = parent
	}
}

func (l *Local) pathForKey(key string, id domain.ID) (string, error) {
	if err := ValidateStorageKey(key, id); err != nil {
		return "", err
	}
	location := filepath.Join(append([]string{l.root}, strings.Split(key, "/")...)...)
	if !within(l.root, location) {
		return "", fmt.Errorf("artifact path escapes storage root")
	}
	return location, nil
}

func within(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
