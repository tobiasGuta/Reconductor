package artifact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
