//go:build !windows

package artifact

import (
	"errors"
	"os"
)

func platformSyncDirectory(path string) (directorySyncResult, error) {
	directory, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil || closeErr != nil {
		return 0, errors.Join(syncErr, closeErr)
	}
	return directorySyncPerformed, nil
}
