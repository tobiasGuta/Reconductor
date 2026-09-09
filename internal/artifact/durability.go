package artifact

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type directorySyncResult uint8

const (
	directorySyncPerformed directorySyncResult = iota + 1
	directorySyncUnsupported
)

type directorySyncFunc func(string) (directorySyncResult, error)

var syncDirectoryEntry directorySyncFunc = platformSyncDirectory

func syncDirectoryChain(start, stop string) error {
	return syncDirectoryChainWith(start, stop, syncDirectoryEntry)
}

func syncDirectoryChainWith(start, stop string, syncDirectory directorySyncFunc) error {
	start, err := filepath.Abs(start)
	if err != nil {
		return fmt.Errorf("resolve directory sync start: %w", err)
	}
	stop, err = filepath.Abs(stop)
	if err != nil {
		return fmt.Errorf("resolve directory sync stop: %w", err)
	}
	relative, err := filepath.Rel(stop, start)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("directory sync stop is not an ancestor of start")
	}
	for current := start; ; current = filepath.Dir(current) {
		result, err := syncDirectory(current)
		if err != nil {
			return fmt.Errorf("sync directory %s: %w", current, err)
		}
		switch result {
		case directorySyncPerformed:
		case directorySyncUnsupported:
			// The platform implementation explicitly reports this limitation;
			// file Sync remains required and supported-operation failures still fail.
		default:
			return fmt.Errorf("sync directory %s: unknown durability result", current)
		}
		if current == stop {
			return nil
		}
	}
}

func nearestExistingDirectory(path string) (string, error) {
	current, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	for {
		info, statErr := os.Stat(current)
		switch {
		case statErr == nil && info.IsDir():
			return current, nil
		case statErr == nil:
			return "", fmt.Errorf("existing ancestor %s is not a directory", current)
		case !os.IsNotExist(statErr):
			return "", statErr
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("no existing directory ancestor for %s", path)
		}
		current = parent
	}
}

func filesystemRoot(path string) (string, error) {
	current, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	for {
		parent := filepath.Dir(current)
		if parent == current {
			return current, nil
		}
		current = parent
	}
}
