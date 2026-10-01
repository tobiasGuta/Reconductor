package artifact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
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
	identity    StoreIdentity
	redactor    *redaction.Redactor
	newID       func() domain.ID
	initialized bool
	rootInfo    os.FileInfo
	markerInfo  os.FileInfo
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

func (l *Local) Identity() StoreIdentity {
	if l == nil {
		return StoreIdentity{}
	}
	return l.identity
}

func (l *Local) OpenVerified(ctx context.Context, reference domain.ResultArtifactRefV1) (io.ReadCloser, error) {
	if l == nil || !l.initialized || reference.ArtifactStoreID != l.storeID {
		return nil, fmt.Errorf("semantic artifact store identity mismatch")
	}
	if err := reference.Validate(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return l.openAuthoritativeArtifact(ctx, reference)
}

// AcquireVerifiedEvidence obtains shared store authority before callers take
// database lineage locks. The guard must remain open through their commit.
func (l *Local) AcquireVerifiedEvidence(ctx context.Context) (VerifiedEvidenceGuard, error) {
	if l == nil || !l.initialized {
		return nil, fmt.Errorf("artifact store is not initialized")
	}
	guard, err := l.AcquirePublisher(ctx, l.identity)
	if err != nil {
		return nil, err
	}
	verified, ok := guard.(VerifiedEvidenceGuard)
	if !ok {
		_ = guard.Close()
		return nil, fmt.Errorf("verified evidence authority is unavailable")
	}
	return verified, nil
}

type verifiedArtifactReader struct {
	file           *os.File
	limited        io.Reader
	hash           hash.Hash
	expectedSize   int64
	expectedDigest []byte
	read           int64
	verified       bool
	verification   error
}

func (r *verifiedArtifactReader) Read(buffer []byte) (int, error) {
	if r.verification != nil {
		return 0, r.verification
	}
	n, err := r.limited.Read(buffer)
	if n > 0 {
		r.read += int64(n)
		_, _ = r.hash.Write(buffer[:n])
	}
	if errors.Is(err, io.EOF) {
		r.verification = r.verify()
		if r.verification != nil {
			return n, r.verification
		}
	}
	return n, err
}

func (r *verifiedArtifactReader) verify() error {
	if r.verified {
		return r.verification
	}
	r.verified = true
	if r.read != r.expectedSize || !bytes.Equal(r.hash.Sum(nil), r.expectedDigest) {
		return fmt.Errorf("semantic artifact integrity mismatch")
	}
	return nil
}

func (r *verifiedArtifactReader) Close() error {
	if r.file == nil {
		return r.verification
	}
	_, drainErr := io.Copy(io.Discard, r)
	verifyErr := r.verify()
	closeErr := r.file.Close()
	r.file = nil
	return errors.Join(drainErr, verifyErr, closeErr)
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

	return l.deleteAuthoritativeArtifact(ctx, storageKey)
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
