package configstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Section identifies a configuration namespace (e.g., "general", "providers").
type Section string

const (
	SectionGeneral   Section = "general"
	SectionProviders Section = "providers"
	SectionSecurity  Section = "security"
	SectionMFA       Section = "mfa"

	// SectionDocumentKey is the default key used to persist a full section document.
	SectionDocumentKey = "__doc"

	defaultLoadTimeout = 5 * time.Second
)

var (
	// ErrNilDB is returned when a store is created without a database handle.
	ErrNilDB = errors.New("configstore: db is nil")
	// ErrVersionMismatch indicates an optimistic-lock check failed during an update.
	ErrVersionMismatch = errors.New("configstore: version mismatch")
)

// Options configure Store behaviour.
type Options struct {
	Defaults    map[Section]json.RawMessage
	LoadTimeout time.Duration
	Now         func() time.Time
}

// UpdateOptions control how a section update is applied.
type UpdateOptions struct {
	Key           string
	UpdatedBy     string
	Reason        string
	ExpectVersion int64
}

// Store provides cached access to the app_config table with optimistic locking.
type Store struct {
	db       *sql.DB
	opts     Options
	mu       sync.RWMutex
	snapshot Snapshot
}

// Snapshot represents a point-in-time view of configuration data.
type Snapshot struct {
	Sections map[Section]SectionSnapshot
	LoadedAt time.Time
}

// SectionSnapshot captures the persisted keys for a section.
type SectionSnapshot struct {
	Items map[string]Item
}

// Item represents one row from app_config.
type Item struct {
	Namespace Section
	Key       string
	Value     json.RawMessage
	Version   int64
	UpdatedAt time.Time
	UpdatedBy string
}

// HistoryEntry represents a single historical revision of a config section.
type HistoryEntry struct {
	Namespace Section
	Key       string
	Value     json.RawMessage
	Version   int64
	UpdatedAt time.Time
	UpdatedBy string
	Reason    string
}

// New initialises a Store and loads the current configuration snapshot.
func New(db *sql.DB, opts Options) (*Store, error) {
	if db == nil {
		return nil, ErrNilDB
	}

	if opts.LoadTimeout <= 0 {
		opts.LoadTimeout = defaultLoadTimeout
	}

	store := &Store{
		db:   db,
		opts: opts,
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.LoadTimeout)
	defer cancel()

	if _, err := store.reload(ctx); err != nil {
		return nil, err
	}
	return store, nil
}

// Reload refreshes the cached snapshot from the database.
func (s *Store) Reload(ctx context.Context) (Snapshot, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	return s.reload(ctx)
}

// Snapshot returns a deep copy of the cached configuration snapshot.
func (s *Store) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneSnapshot(s.snapshot)
}

// TotalItems returns the total number of entries across all sections.
func (s Snapshot) TotalItems() int {
	total := 0
	for _, sec := range s.Sections {
		total += len(sec.Items)
	}
	return total
}

// Section decodes the stored JSON document for a section into dest, layering defaults first.
func (s *Store) Section(section Section, dest any) (int64, error) {
	return s.SectionWithKey(section, SectionDocumentKey, dest)
}

// SectionWithKey decodes a specific section/key pair into dest with defaults applied.
func (s *Store) SectionWithKey(section Section, key string, dest any) (int64, error) {
	raw, version := s.Raw(section, key)
	if defaults := s.opts.Defaults[section]; len(defaults) > 0 {
		if err := json.Unmarshal(defaults, dest); err != nil {
			return 0, fmt.Errorf("configstore: decode defaults for %s: %w", section, err)
		}
	}
	if len(raw) == 0 {
		return version, nil
	}
	if err := json.Unmarshal(raw, dest); err != nil {
		return 0, fmt.Errorf("configstore: decode section %s: %w", section, err)
	}
	return version, nil
}

// Raw returns a copy of the raw JSON payload and version for the requested section/key.
func (s *Store) Raw(section Section, key string) (json.RawMessage, int64) {
	if key == "" {
		key = SectionDocumentKey
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	sec, ok := s.snapshot.Sections[section]
	if !ok {
		return nil, 0
	}
	item, ok := sec.Items[key]
	if !ok {
		return nil, 0
	}
	return cloneRaw(item.Value), item.Version
}

// UpsertSection marshals payload and persists it under the given section/key, enforcing version checks.
func (s *Store) UpsertSection(ctx context.Context, section Section, payload any, uopts UpdateOptions) (Snapshot, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	key := strings.TrimSpace(uopts.Key)
	if key == "" {
		key = SectionDocumentKey
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return Snapshot{}, fmt.Errorf("configstore: marshal section %s: %w", section, err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Snapshot{}, err
	}
	defer tx.Rollback()

	var (
		currentVersion sql.NullInt64
	)

	err = tx.QueryRowContext(ctx, `
SELECT version
  FROM app_config
 WHERE namespace = $1
   AND key = $2
 FOR UPDATE
`, string(section), key).Scan(&currentVersion)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return Snapshot{}, err
		}
		err = nil
	}

	if currentVersion.Valid && uopts.ExpectVersion > 0 && currentVersion.Int64 != uopts.ExpectVersion {
		return Snapshot{}, ErrVersionMismatch
	}
	if !currentVersion.Valid && uopts.ExpectVersion > 0 {
		return Snapshot{}, ErrVersionMismatch
	}

	newVersion := int64(1)
	if currentVersion.Valid {
		newVersion = currentVersion.Int64 + 1
	}

	updatedBy := strings.TrimSpace(uopts.UpdatedBy)
	reason := strings.TrimSpace(uopts.Reason)

	if _, err := tx.ExecContext(ctx, `
INSERT INTO app_config (namespace, key, value, version, updated_at, updated_by)
VALUES ($1, $2, $3, $4, now(), NULLIF($5, ''))
ON CONFLICT (namespace, key) DO UPDATE
   SET value = EXCLUDED.value,
       version = EXCLUDED.version,
       updated_at = now(),
       updated_by = EXCLUDED.updated_by
`, string(section), key, raw, newVersion, updatedBy); err != nil {
		return Snapshot{}, err
	}

	if _, err := tx.ExecContext(ctx, `
INSERT INTO app_config_history (namespace, key, value, version, updated_at, updated_by, change_reason)
VALUES ($1, $2, $3, $4, now(), NULLIF($5, ''), NULLIF($6, ''))
`, string(section), key, raw, newVersion, updatedBy, reason); err != nil {
		return Snapshot{}, err
	}

	if err := tx.Commit(); err != nil {
		return Snapshot{}, err
	}

	return s.reload(ctx)
}

func (s *Store) reload(ctx context.Context) (Snapshot, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT namespace, key, value, version, updated_at, updated_by
  FROM app_config
 ORDER BY namespace, key
`)
	if err != nil {
		return Snapshot{}, err
	}
	defer rows.Close()

	sections := make(map[Section]SectionSnapshot)

	for rows.Next() {
		var (
			namespace string
			key       string
			value     []byte
			version   int64
			updatedAt time.Time
			updatedBy sql.NullString
		)

		if err := rows.Scan(&namespace, &key, &value, &version, &updatedAt, &updatedBy); err != nil {
			return Snapshot{}, err
		}

		ns := Section(strings.TrimSpace(namespace))
		if ns == "" {
			continue
		}

		item := Item{
			Namespace: ns,
			Key:       key,
			Value:     cloneRaw(json.RawMessage(value)),
			Version:   version,
			UpdatedAt: updatedAt.UTC(),
		}
		if updatedBy.Valid {
			item.UpdatedBy = updatedBy.String
		}

		sec := sections[ns]
		if sec.Items == nil {
			sec.Items = make(map[string]Item)
		}
		sec.Items[key] = item
		sections[ns] = sec
	}

	if err := rows.Err(); err != nil {
		return Snapshot{}, err
	}

	snap := Snapshot{
		Sections: sections,
		LoadedAt: s.now(),
	}

	s.mu.Lock()
	s.snapshot = snap
	s.mu.Unlock()

	return cloneSnapshot(snap), nil
}

func (s *Store) now() time.Time {
	if s.opts.Now != nil {
		return s.opts.Now()
	}
	return time.Now().UTC()
}

func cloneSnapshot(src Snapshot) Snapshot {
	out := Snapshot{
		LoadedAt: src.LoadedAt,
	}
	if len(src.Sections) == 0 {
		return out
	}

	out.Sections = make(map[Section]SectionSnapshot, len(src.Sections))
	for section, sec := range src.Sections {
		items := make(map[string]Item, len(sec.Items))
		for key, item := range sec.Items {
			items[key] = Item{
				Namespace: item.Namespace,
				Key:       item.Key,
				Value:     cloneRaw(item.Value),
				Version:   item.Version,
				UpdatedAt: item.UpdatedAt,
				UpdatedBy: item.UpdatedBy,
			}
		}
		out.Sections[section] = SectionSnapshot{Items: items}
	}
	return out
}

func cloneRaw(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	buf := make([]byte, len(raw))
	copy(buf, raw)
	return json.RawMessage(buf)
}

// History returns the most recent change entries for the given section/document key.
func (s *Store) History(ctx context.Context, section Section, key string, limit int) ([]HistoryEntry, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if limit <= 0 {
		limit = 20
	}
	if limit > 200 {
		limit = 200
	}
	key = strings.TrimSpace(key)
	if key == "" {
		key = SectionDocumentKey
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT namespace, key, value, version, updated_at, updated_by, change_reason
  FROM app_config_history
 WHERE namespace = $1
   AND key = $2
 ORDER BY id DESC
 LIMIT $3
`, string(section), key, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []HistoryEntry
	for rows.Next() {
		var (
			ns        string
			k         string
			value     []byte
			version   int64
			updatedAt time.Time
			updatedBy sql.NullString
			reason    sql.NullString
		)
		if err := rows.Scan(&ns, &k, &value, &version, &updatedAt, &updatedBy, &reason); err != nil {
			return nil, err
		}
		entry := HistoryEntry{
			Namespace: Section(strings.TrimSpace(ns)),
			Key:       strings.TrimSpace(k),
			Value:     cloneRaw(json.RawMessage(value)),
			Version:   version,
			UpdatedAt: updatedAt.UTC(),
		}
		if updatedBy.Valid {
			entry.UpdatedBy = strings.TrimSpace(updatedBy.String)
		}
		if reason.Valid {
			entry.Reason = strings.TrimSpace(reason.String)
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}
