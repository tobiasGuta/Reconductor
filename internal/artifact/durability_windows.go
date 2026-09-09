//go:build windows

package artifact

// Windows does not expose the directory-fsync contract used by Unix filesystems.
// Artifact and marker files are still flushed with os.File.Sync; callers receive
// this explicit outcome instead of treating a directory flush as performed.
func platformSyncDirectory(string) (directorySyncResult, error) {
	return directorySyncUnsupported, nil
}
