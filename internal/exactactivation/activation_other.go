//go:build !linux

package exactactivation

type WorkerListener struct{}

func AcquireWorkerListener() (*WorkerListener, error) { return nil, ErrUnsupported }
func (l *WorkerListener) Close() error                { return nil }
func VerifyPeerCredentials() error                    { return ErrUnsupported }
