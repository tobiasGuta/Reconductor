package resultadmission

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"sync"

	"github.com/tobiasGuta/Reconductor/internal/artifact"
)

type byteSource struct {
	data   []byte
	digest [32]byte
}

func newByteSource(data []byte) *byteSource {
	owned := append([]byte(nil), data...)
	return &byteSource{data: owned, digest: sha256.Sum256(owned)}
}
func (s *byteSource) Open() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(s.data)), nil }
func (s *byteSource) SizeBytes() int64             { return int64(len(s.data)) }
func (s *byteSource) SHA256() [32]byte             { return s.digest }

const preparedMemoryLimit = 64 * 1024

func newPreparedSource(data []byte) (artifact.ReplayableSource, error) {
	if len(data) <= preparedMemoryLimit {
		return newByteSource(data), nil
	}
	file, err := os.CreateTemp("", "reconductor-result-preparation-*")
	if err != nil {
		return nil, err
	}
	path := file.Name()
	cleanup := func(cause error) (artifact.ReplayableSource, error) {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, cause
	}
	if err := file.Chmod(0600); err != nil {
		return cleanup(err)
	}
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(file, hash), bytes.NewReader(data))
	if err != nil || written != int64(len(data)) {
		return cleanup(fmt.Errorf("prepare result evidence: %w", err))
	}
	if err := file.Sync(); err != nil {
		return cleanup(err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return nil, err
	}
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return &temporarySource{path: path, size: written, digest: digest}, nil
}

type temporarySource struct {
	path   string
	size   int64
	digest [32]byte
	once   sync.Once
	err    error
}

func (s *temporarySource) Open() (io.ReadCloser, error) { return os.Open(s.path) }
func (s *temporarySource) SizeBytes() int64             { return s.size }
func (s *temporarySource) SHA256() [32]byte             { return s.digest }
func (s *temporarySource) Close() error {
	s.once.Do(func() { s.err = os.Remove(s.path) })
	return s.err
}

type DiagnosticSectionKind uint8

const (
	CompleteDiagnostic    DiagnosticSectionKind = 1
	InvalidSemanticOutput DiagnosticSectionKind = 2
)

var diagnosticMagic = []byte("RCDIAGV1")

type DiagnosticSection struct {
	Kind   DiagnosticSectionKind
	Source interface {
		Open() (io.ReadCloser, error)
		SizeBytes() int64
		SHA256() [32]byte
	}
}
type diagnosticBundleSource struct {
	sections []DiagnosticSection
	size     int64
	digest   [32]byte
}

func NewDiagnosticBundleSource(sections []DiagnosticSection) (*diagnosticBundleSource, error) {
	if len(sections) < 1 || len(sections) > 2 {
		return nil, fmt.Errorf("diagnostic bundle requires one or two sections")
	}
	owned := append([]DiagnosticSection(nil), sections...)
	last := DiagnosticSectionKind(0)
	size := int64(9)
	for _, section := range owned {
		if section.Kind != CompleteDiagnostic && section.Kind != InvalidSemanticOutput || section.Kind <= last || section.Source == nil || section.Source.SizeBytes() < 0 {
			return nil, fmt.Errorf("invalid diagnostic section")
		}
		last = section.Kind
		if section.Source.SizeBytes() > math.MaxInt64-41 || size > math.MaxInt64-41-section.Source.SizeBytes() {
			return nil, fmt.Errorf("diagnostic bundle size overflow")
		}
		size += 41 + section.Source.SizeBytes()
	}
	source := &diagnosticBundleSource{sections: owned, size: size}
	reader, err := source.openUnverified()
	if err != nil {
		return nil, err
	}
	hash := sha256.New()
	written, copyErr := io.Copy(hash, reader)
	closeErr := reader.Close()
	if copyErr != nil || closeErr != nil || written != size {
		return nil, fmt.Errorf("hash diagnostic bundle: %w", firstError(copyErr, closeErr))
	}
	copy(source.digest[:], hash.Sum(nil))
	return source, nil
}
func (s *diagnosticBundleSource) SizeBytes() int64             { return s.size }
func (s *diagnosticBundleSource) SHA256() [32]byte             { return s.digest }
func (s *diagnosticBundleSource) Open() (io.ReadCloser, error) { return s.openUnverified() }
func (s *diagnosticBundleSource) Close() error {
	var result error
	for _, section := range s.sections {
		if closer, ok := section.Source.(io.Closer); ok {
			result = errors.Join(result, closer.Close())
		}
	}
	return result
}
func (s *diagnosticBundleSource) openUnverified() (io.ReadCloser, error) {
	readers := []io.Reader{bytes.NewReader(diagnosticMagic), bytes.NewReader([]byte{byte(len(s.sections))})}
	closers := []io.Closer{}
	for _, section := range s.sections {
		reader, err := section.Source.Open()
		if err != nil {
			for _, c := range closers {
				_ = c.Close()
			}
			return nil, err
		}
		closers = append(closers, reader)
		header := make([]byte, 41)
		header[0] = byte(section.Kind)
		length := uint64(section.Source.SizeBytes())
		for i := 0; i < 8; i++ {
			header[8-i] = byte(length)
			length >>= 8
		}
		sum := section.Source.SHA256()
		copy(header[9:], sum[:])
		readers = append(readers, bytes.NewReader(header), reader)
	}
	return &multiReadCloser{Reader: io.MultiReader(readers...), closers: closers}, nil
}

type multiReadCloser struct {
	io.Reader
	closers []io.Closer
}

func (m *multiReadCloser) Close() error {
	var result error
	for _, c := range m.closers {
		if err := c.Close(); err != nil && result == nil {
			result = err
		}
	}
	return result
}
func firstError(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

func VerifyDiagnosticBundle(reader io.Reader, size int64) error {
	if size < 50 {
		return fmt.Errorf("diagnostic bundle is truncated")
	}
	limited := io.LimitReader(reader, size+1)
	magic := make([]byte, 8)
	if _, err := io.ReadFull(limited, magic); err != nil || !bytes.Equal(magic, diagnosticMagic) {
		return fmt.Errorf("invalid diagnostic bundle magic")
	}
	count := make([]byte, 1)
	if _, err := io.ReadFull(limited, count); err != nil || count[0] < 1 || count[0] > 2 {
		return fmt.Errorf("invalid diagnostic section count")
	}
	consumed := int64(9)
	last := byte(0)
	for i := 0; i < int(count[0]); i++ {
		header := make([]byte, 41)
		if _, err := io.ReadFull(limited, header); err != nil {
			return fmt.Errorf("truncated diagnostic section header")
		}
		consumed += 41
		if header[0] != 1 && header[0] != 2 || header[0] <= last {
			return fmt.Errorf("invalid diagnostic section kind/order")
		}
		last = header[0]
		length := uint64(0)
		for _, b := range header[1:9] {
			length = length<<8 | uint64(b)
		}
		if length > math.MaxInt64 || int64(length) > size-consumed {
			return fmt.Errorf("diagnostic section length overflow or truncation")
		}
		hash := sha256.New()
		written, err := io.CopyN(hash, limited, int64(length))
		if err != nil || written != int64(length) {
			return fmt.Errorf("truncated diagnostic section")
		}
		consumed += written
		if !bytes.Equal(hash.Sum(nil), header[9:]) {
			return fmt.Errorf("diagnostic section digest mismatch")
		}
	}
	if consumed != size {
		return fmt.Errorf("diagnostic bundle has trailing data")
	}
	extra := make([]byte, 1)
	if n, _ := limited.Read(extra); n != 0 {
		return fmt.Errorf("diagnostic bundle has trailing data")
	}
	return nil
}
