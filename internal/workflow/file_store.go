package workflow

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type FileStore struct{ Root string }

type CheckpointDecodeError struct{ Err error }

func (e *CheckpointDecodeError) Error() string { return "decode workflow checkpoint: " + e.Err.Error() }
func (e *CheckpointDecodeError) Unwrap() error { return e.Err }

func (s FileStore) Save(_ context.Context, state *State) error {
	if state == nil || state.Run.ID == "" {
		return fmt.Errorf("run state id is required")
	}
	root, err := filepath.Abs(s.Root)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return err
	}
	target := filepath.Join(root, string(state.Run.ID)+".json")
	rel, err := filepath.Rel(root, target)
	if err != nil || strings.HasPrefix(rel, "..") {
		return fmt.Errorf("run state path escapes root")
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, target)
}
func (s FileStore) Load(id string) (*State, error) {
	data, err := os.ReadFile(filepath.Join(s.Root, filepath.Base(id)+".json"))
	if err != nil {
		return nil, err
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, &CheckpointDecodeError{Err: err}
	}
	return &state, nil
}
