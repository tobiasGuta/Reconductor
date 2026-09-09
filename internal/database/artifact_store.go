package database

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/domain"
)

var (
	ErrArtifactStoreNotFound             = artifact.ErrStoreRegistrationNotFound
	ErrArtifactStoreRegistrationConflict = errors.New("artifact store registration conflict")
)

func (s *Store) ArtifactStore(ctx context.Context, id domain.ID) (domain.ArtifactStore, error) {
	if _, err := domain.ParseID(string(id)); err != nil {
		return domain.ArtifactStore{}, fmt.Errorf("artifact store ID is not canonical: %w", err)
	}
	var item domain.ArtifactStore
	err := s.Pool.QueryRow(ctx, `SELECT id,incarnation_nonce,backend_kind,marker_format,marker_version,created_at FROM artifact_stores WHERE id=$1`, id).Scan(
		&item.ID,
		&item.IncarnationNonce,
		&item.BackendKind,
		&item.MarkerFormat,
		&item.MarkerVersion,
		&item.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ArtifactStore{}, ErrArtifactStoreNotFound
	}
	return item, err
}

func (s *Store) RegisterArtifactStore(ctx context.Context, registration domain.ArtifactStoreRegistration) (domain.ArtifactStore, error) {
	if err := validateArtifactStoreRegistration(registration); err != nil {
		return domain.ArtifactStore{}, err
	}
	var insertErr error
	if _, err := s.Pool.Exec(ctx, `INSERT INTO artifact_stores(id,incarnation_nonce,backend_kind,marker_format,marker_version) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, registration.ID, registration.IncarnationNonce, registration.BackendKind, registration.MarkerFormat, registration.MarkerVersion); err != nil {
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) && postgresError.Code == "23505" {
			insertErr = err
		} else {
			return domain.ArtifactStore{}, err
		}
	}
	var item domain.ArtifactStore
	err := s.Pool.QueryRow(ctx, `SELECT id,incarnation_nonce,backend_kind,marker_format,marker_version,created_at
		FROM artifact_stores
		WHERE id=$1 OR incarnation_nonce=$2
		ORDER BY CASE WHEN id=$1 THEN 0 ELSE 1 END
		LIMIT 1`, registration.ID, registration.IncarnationNonce).Scan(
		&item.ID,
		&item.IncarnationNonce,
		&item.BackendKind,
		&item.MarkerFormat,
		&item.MarkerVersion,
		&item.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		if insertErr != nil {
			return domain.ArtifactStore{}, fmt.Errorf("insert artifact store: %w", insertErr)
		}
		return domain.ArtifactStore{}, fmt.Errorf("artifact store registration failed: neither store ID nor incarnation nonce found")
	}
	if err != nil {
		return domain.ArtifactStore{}, err
	}
	if item.ID == registration.ID {
		if item.IncarnationNonce == registration.IncarnationNonce &&
			item.BackendKind == registration.BackendKind &&
			item.MarkerFormat == registration.MarkerFormat &&
			item.MarkerVersion == registration.MarkerVersion {
			return item, nil
		}
		return domain.ArtifactStore{}, fmt.Errorf("%w: StoreID is already registered with different identity", ErrArtifactStoreRegistrationConflict)
	}
	return domain.ArtifactStore{}, fmt.Errorf("%w: incarnation nonce is already registered", ErrArtifactStoreRegistrationConflict)
}

func validateArtifactStoreRegistration(registration domain.ArtifactStoreRegistration) error {
	if _, err := domain.ParseID(string(registration.ID)); err != nil {
		return fmt.Errorf("artifact store ID is not canonical: %w", err)
	}
	if _, err := domain.ParseID(string(registration.IncarnationNonce)); err != nil {
		return fmt.Errorf("artifact store incarnation nonce is not canonical: %w", err)
	}
	return nil
}
