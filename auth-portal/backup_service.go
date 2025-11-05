package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"auth-portal/configstore"
)

const (
	defaultBackupDirName   = "backups"
	legacyScheduleFilename = "schedule.json"
)

var (
	errUnknownBackupSection = errors.New("unknown backup section")
)

type backupService struct {
	store *configstore.Store
	dir   string

	mu       sync.RWMutex
	schedule backupSchedule
	nextRun  time.Time
	version  int64

	stopCh   chan struct{}
	stopped  chan struct{}
	runCheck chan struct{}
}

type backupSchedule struct {
	Enabled   bool      `json:"enabled"`
	Frequency string    `json:"frequency"`
	TimeOfDay string    `json:"timeOfDay,omitempty"`
	DayOfWeek string    `json:"dayOfWeek,omitempty"`
	Minute    int       `json:"minute,omitempty"`
	Sections  []string  `json:"sections"`
	Retention int       `json:"retention"`
	LastRun   time.Time `json:"lastRun,omitempty"`
}

type backupDocument struct {
	CreatedAt time.Time                       `json:"createdAt"`
	CreatedBy string                          `json:"createdBy,omitempty"`
	Sections  map[string]backupDocumentRecord `json:"sections"`
}

type backupDocumentRecord struct {
	Version int64           `json:"version"`
	Config  json.RawMessage `json:"config"`
}

type backupMetadata struct {
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"createdAt"`
	CreatedBy string    `json:"createdBy,omitempty"`
	Sections  []string  `json:"sections"`
	Size      int64     `json:"size"`
}

func newBackupService(store *configstore.Store, dir string) (*backupService, error) {
	if store == nil {
		return nil, errors.New("backup service requires config store")
	}
	dir = strings.TrimSpace(dir)
	if dir == "" {
		dir = defaultBackupDirName
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(absDir, 0o755); err != nil {
		return nil, err
	}

	svc := &backupService{
		store:    store,
		dir:      absDir,
		stopCh:   make(chan struct{}),
		stopped:  make(chan struct{}),
		runCheck: make(chan struct{}, 1),
	}

	if err := svc.loadSchedule(context.Background()); err != nil {
		return nil, err
	}
	svc.calculateNextRun(time.Now().UTC())
	go svc.loop()
	return svc, nil
}

func (s *backupService) Close() {
	select {
	case <-s.stopCh:
		return
	default:
		close(s.stopCh)
		<-s.stopped
	}
}

func (s *backupService) loop() {
	defer close(s.stopped)

	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.maybeRunScheduled()
		case <-s.runCheck:
			s.maybeRunScheduled()
		case <-s.stopCh:
			return
		}
	}
}

func (s *backupService) maybeRunScheduled() {
	s.mu.Lock()
	sched := s.schedule
	nextRun := s.nextRun
	s.mu.Unlock()

	if !sched.Enabled {
		return
	}
	if nextRun.IsZero() || time.Now().UTC().Before(nextRun) {
		return
	}

	now := time.Now().UTC()
	meta, err := s.createBackup(context.Background(), sched.Sections, "system")
	if err != nil {
		log.Printf("Backup schedule run failed: %v", err)
		s.calculateNextRun(now.Add(5 * time.Minute))
		return
	}

	if sched.Retention > 0 {
		if err := s.enforceRetention(sched.Retention); err != nil {
			log.Printf("Backup retention enforcement failed: %v", err)
		}
	}

	s.mu.Lock()
	s.schedule.LastRun = meta.CreatedAt
	if err := s.persistScheduleLocked(context.Background(), "system"); err != nil {
		log.Printf("Failed to persist backup schedule: %v", err)
	}
	s.calculateNextRunLocked(meta.CreatedAt)
	s.mu.Unlock()
}

func (s *backupService) calculateNextRun(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calculateNextRunLocked(now)
}

func (s *backupService) calculateNextRunLocked(now time.Time) {
	next, err := computeNextRun(s.schedule, now)
	if err != nil {
		log.Printf("Backup schedule compute error: %v", err)
		s.nextRun = time.Time{}
		return
	}
	s.nextRun = next
}

func (s *backupService) loadSchedule(ctx context.Context) error {
	raw, version := s.store.Raw(configstore.SectionBackups, configstore.SectionDocumentKey)
	if raw == nil {
		base := defaultBackupSchedule()
		legacyPath := filepath.Join(s.dir, legacyScheduleFilename)
		if data, err := os.ReadFile(legacyPath); err == nil {
			var legacy backupSchedule
			if err := json.Unmarshal(data, &legacy); err == nil {
				base = legacy
			} else {
				log.Printf("Legacy backup schedule decode failed: %v", err)
			}
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("Legacy backup schedule read failed: %v", err)
		}

		normalized, err := normalizeBackupSchedule(base)
		if err != nil {
			return err
		}
		s.mu.Lock()
		s.schedule = normalized
		s.version = 0
		if err := s.persistScheduleLocked(ctx, "system"); err != nil {
			s.mu.Unlock()
			return err
		}
		s.mu.Unlock()
		_ = os.Remove(legacyPath)
		return nil
	}

	var sched backupSchedule
	if err := json.Unmarshal(raw, &sched); err != nil {
		return err
	}

	normalized, err := normalizeBackupSchedule(sched)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.schedule = normalized
	s.version = version
	s.mu.Unlock()
	return nil
}

func (s *backupService) persistScheduleLocked(ctx context.Context, actor string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	normalized, err := normalizeBackupSchedule(s.schedule)
	if err != nil {
		return err
	}
	s.schedule = normalized
	updatedBy := strings.TrimSpace(actor)
	if updatedBy == "" {
		updatedBy = "system"
	}
	snap, err := s.store.UpsertSection(ctx, configstore.SectionBackups, normalized, configstore.UpdateOptions{
		UpdatedBy:     updatedBy,
		ExpectVersion: s.version,
	})
	if err != nil {
		return err
	}
	if sec, ok := snap.Sections[configstore.SectionBackups]; ok {
		if item, ok := sec.Items[configstore.SectionDocumentKey]; ok {
			s.version = item.Version
		}
	}
	return nil
}

func (s *backupService) ScheduleSnapshot() (backupSchedule, time.Time) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sched := s.schedule
	sched.Sections = append([]string(nil), sched.Sections...)
	return sched, s.nextRun
}

func (s *backupService) UpdateSchedule(ctx context.Context, sched backupSchedule, actor string) (backupSchedule, time.Time, error) {
	normalized, err := normalizeBackupSchedule(sched)
	if err != nil {
		return backupSchedule{}, time.Time{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	normalized.LastRun = s.schedule.LastRun
	s.schedule = normalized
	if err := s.persistScheduleLocked(ctx, actor); err != nil {
		return backupSchedule{}, time.Time{}, err
	}
	s.calculateNextRunLocked(time.Now().UTC())
	select {
	case s.runCheck <- struct{}{}:
	default:
	}
	snapshot := s.schedule
	snapshot.Sections = append([]string(nil), snapshot.Sections...)
	return snapshot, s.nextRun, nil
}

func (s *backupService) CreateManualBackup(ctx context.Context, sections []string, author string) (backupMetadata, error) {
	meta, err := s.createBackup(ctx, sections, author)
	if err != nil {
		return backupMetadata{}, err
	}

	s.mu.RLock()
	retention := s.schedule.Retention
	s.mu.RUnlock()

	if retention > 0 {
		if err := s.enforceRetention(retention); err != nil {
			log.Printf("Backup retention enforcement failed: %v", err)
		}
	}
	return meta, nil
}

func (s *backupService) createBackup(ctx context.Context, sections []string, author string) (backupMetadata, error) {
	validSections := normalizeBackupSections(sections)
	if len(validSections) == 0 {
		validSections = []string{"providers", "security", "mfa", "app-settings"}
	}

	doc := backupDocument{
		CreatedAt: time.Now().UTC(),
		CreatedBy: strings.TrimSpace(author),
		Sections:  make(map[string]backupDocumentRecord, len(validSections)),
	}

	for _, sectionKey := range validSections {
		storeSection, err := sectionFromKey(sectionKey)
		if err != nil {
			return backupMetadata{}, err
		}
		raw, version := s.store.Raw(storeSection, configstore.SectionDocumentKey)
		if raw == nil {
			raw = json.RawMessage([]byte("{}"))
		}
		doc.Sections[sectionKey] = backupDocumentRecord{
			Version: version,
			Config:  cloneRawMessage(raw),
		}
	}

	filename := fmt.Sprintf("backup-%s.json", doc.CreatedAt.Format("20060102-150405"))
	path := filepath.Join(s.dir, filename)
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return backupMetadata{}, err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return backupMetadata{}, err
	}

	info, err := os.Stat(path)
	if err != nil {
		return backupMetadata{}, err
	}

	return backupMetadata{
		Name:      filename,
		CreatedAt: doc.CreatedAt,
		CreatedBy: doc.CreatedBy,
		Sections:  append([]string(nil), validSections...),
		Size:      info.Size(),
	}, nil
}

func (s *backupService) enforceRetention(retention int) error {
	if retention <= 0 {
		return nil
	}
	files, err := s.listBackupsUnlocked()
	if err != nil {
		return err
	}
	if len(files) <= retention {
		return nil
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i].CreatedAt.Before(files[j].CreatedAt)
	})
	for i := 0; i < len(files)-retention; i++ {
		_ = os.Remove(filepath.Join(s.dir, files[i].Name))
	}
	return nil
}

func (s *backupService) ListBackups() ([]backupMetadata, error) {
	return s.listBackupsUnlocked()
}

func (s *backupService) listBackupsUnlocked() ([]backupMetadata, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}

	var metas []backupMetadata
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.EqualFold(name, legacyScheduleFilename) {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(name), ".json") {
			continue
		}
		meta, err := s.readBackupMetadata(entry, name)
		if err != nil {
			log.Printf("Skipping backup %s: %v", name, err)
			continue
		}
		metas = append(metas, meta)
	}

	sort.Slice(metas, func(i, j int) bool {
		return metas[i].CreatedAt.After(metas[j].CreatedAt)
	})
	return metas, nil
}

func (s *backupService) readBackupMetadata(entry fs.DirEntry, name string) (backupMetadata, error) {
	path := filepath.Join(s.dir, name)
	data, err := os.ReadFile(path)
	if err != nil {
		return backupMetadata{}, err
	}
	var doc backupDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return backupMetadata{}, err
	}
	info, err := entry.Info()
	if err != nil {
		return backupMetadata{}, err
	}
	sections := make([]string, 0, len(doc.Sections))
	for key := range doc.Sections {
		sections = append(sections, key)
	}
	sort.Strings(sections)
	return backupMetadata{
		Name:      name,
		CreatedAt: doc.CreatedAt.UTC(),
		CreatedBy: strings.TrimSpace(doc.CreatedBy),
		Sections:  sections,
		Size:      info.Size(),
	}, nil
}

func (s *backupService) DeleteBackup(name string) error {
	path, err := s.resolveBackupPath(name)
	if err != nil {
		return err
	}
	return os.Remove(path)
}

func (s *backupService) OpenBackup(name string) (io.ReadCloser, time.Time, error) {
	path, err := s.resolveBackupPath(name)
	if err != nil {
		return nil, time.Time{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, time.Time{}, err
	}
	var doc backupDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, time.Time{}, err
	}
	return io.NopCloser(bytes.NewReader(data)), doc.CreatedAt.UTC(), nil
}

func (s *backupService) RestoreBackup(ctx context.Context, name, actor string) (RuntimeConfig, error) {
	path, err := s.resolveBackupPath(name)
	if err != nil {
		return RuntimeConfig{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return RuntimeConfig{}, err
	}
	var doc backupDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return RuntimeConfig{}, err
	}

	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "admin"
	}

	for key, record := range doc.Sections {
		storeSection, err := sectionFromKey(key)
		if err != nil {
			return RuntimeConfig{}, err
		}
		if record.Config == nil {
			continue
		}

		payload, err := decodeSectionPayload(key, record.Config)
		if err != nil {
			return RuntimeConfig{}, err
		}

		if _, err := s.store.UpsertSection(ctx, storeSection, payload, configstore.UpdateOptions{
			UpdatedBy: actor,
			Reason:    fmt.Sprintf("restore from backup %s", name),
		}); err != nil {
			return RuntimeConfig{}, err
		}
	}

	cfg, err := loadRuntimeConfig(s.store)
	if err != nil {
		return RuntimeConfig{}, err
	}
	applyRuntimeConfig(cfg)
	return cfg, nil
}

func decodeSectionPayload(key string, raw json.RawMessage) (any, error) {
	switch key {
	case "providers":
		var cfg ProvidersConfig
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &cfg); err != nil {
				return nil, err
			}
		}
		normalizeProvidersConfig(&cfg)
		if err := validateProvidersConfig(cfg); err != nil {
			return nil, err
		}
		return cfg, nil
	case "security":
		var cfg SecurityConfig
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &cfg); err != nil {
				return nil, err
			}
		}
		normalizeSecurityConfig(&cfg)
		if err := validateSecurityConfig(cfg); err != nil {
			return nil, err
		}
		return cfg, nil
	case "mfa":
		var cfg MFAConfig
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &cfg); err != nil {
				return nil, err
			}
		}
		normalizeMFAConfig(&cfg)
		if err := validateMFAConfig(cfg); err != nil {
			return nil, err
		}
		return cfg, nil
	case "app-settings":
		var cfg AppSettingsConfig
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &cfg); err != nil {
				return nil, err
			}
		}
		normalizeAppSettingsConfig(&cfg)
		if err := validateAppSettingsConfig(cfg); err != nil {
			return nil, err
		}
		return cfg, nil
	default:
		return nil, errUnknownBackupSection
	}
}

func defaultBackupSchedule() backupSchedule {
	return backupSchedule{
		Enabled:   false,
		Frequency: "daily",
		TimeOfDay: "02:00",
		DayOfWeek: "sunday",
		Minute:    0,
		Sections:  []string{"providers", "security", "mfa", "app-settings"},
		Retention: 30,
	}
}

func normalizeBackupSchedule(sched backupSchedule) (backupSchedule, error) {
	normalized := backupSchedule{
		Enabled:   sched.Enabled,
		Frequency: strings.ToLower(strings.TrimSpace(sched.Frequency)),
		TimeOfDay: strings.TrimSpace(sched.TimeOfDay),
		DayOfWeek: strings.ToLower(strings.TrimSpace(sched.DayOfWeek)),
		Minute:    sched.Minute,
		Sections:  normalizeBackupSections(sched.Sections),
		Retention: sched.Retention,
		LastRun:   sched.LastRun,
	}

	if normalized.Frequency == "" {
		normalized.Frequency = "daily"
	}
	switch normalized.Frequency {
	case "hourly", "daily", "weekly":
	default:
		return backupSchedule{}, fmt.Errorf("unsupported frequency %q", normalized.Frequency)
	}

	if normalized.Retention < 0 {
		normalized.Retention = 0
	}
	if normalized.Frequency == "hourly" {
		if normalized.Minute < 0 || normalized.Minute > 59 {
			normalized.Minute = 0
		}
		normalized.TimeOfDay = ""
		normalized.DayOfWeek = ""
	} else {
		if normalized.TimeOfDay == "" {
			normalized.TimeOfDay = "02:00"
		}
		if _, _, err := parseTimeOfDay(normalized.TimeOfDay); err != nil {
			return backupSchedule{}, err
		}
		if normalized.Frequency == "weekly" {
			if normalized.DayOfWeek == "" {
				normalized.DayOfWeek = "sunday"
			}
			if _, err := parseWeekday(normalized.DayOfWeek); err != nil {
				return backupSchedule{}, err
			}
		} else {
			normalized.DayOfWeek = ""
		}
		normalized.Minute = 0
	}

	if len(normalized.Sections) == 0 {
		normalized.Sections = []string{"providers", "security", "mfa", "app-settings"}
	}
	return normalized, nil
}

func normalizeBackupSections(sections []string) []string {
	if len(sections) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(sections))
	for _, section := range sections {
		key := strings.ToLower(strings.TrimSpace(section))
		switch key {
		case "providers", "security", "mfa", "app-settings":
			set[key] = struct{}{}
		}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func parseTimeOfDay(input string) (int, int, error) {
	parts := strings.Split(input, ":")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid time of day %q", input)
	}
	hour, err := strconv.Atoi(parts[0])
	if err != nil || hour < 0 || hour > 23 {
		return 0, 0, fmt.Errorf("invalid hour in time of day %q", input)
	}
	minute, err := strconv.Atoi(parts[1])
	if err != nil || minute < 0 || minute > 59 {
		return 0, 0, fmt.Errorf("invalid minute in time of day %q", input)
	}
	return hour, minute, nil
}

func parseWeekday(value string) (time.Weekday, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "sunday":
		return time.Sunday, nil
	case "monday":
		return time.Monday, nil
	case "tuesday":
		return time.Tuesday, nil
	case "wednesday":
		return time.Wednesday, nil
	case "thursday":
		return time.Thursday, nil
	case "friday":
		return time.Friday, nil
	case "saturday":
		return time.Saturday, nil
	default:
		return time.Sunday, fmt.Errorf("invalid weekday %q", value)
	}
}

func computeNextRun(sched backupSchedule, from time.Time) (time.Time, error) {
	if !sched.Enabled {
		return time.Time{}, nil
	}
	now := from.UTC()
	switch sched.Frequency {
	case "hourly":
		minute := sched.Minute
		base := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), minute, 0, 0, time.UTC)
		if !base.After(now) {
			base = base.Add(time.Hour)
			base = time.Date(base.Year(), base.Month(), base.Day(), base.Hour(), minute, 0, 0, time.UTC)
		}
		return base, nil
	case "daily":
		hour, minute, err := parseTimeOfDay(sched.TimeOfDay)
		if err != nil {
			return time.Time{}, err
		}
		next := time.Date(now.Year(), now.Month(), now.Day(), hour, minute, 0, 0, time.UTC)
		if !next.After(now) {
			next = next.Add(24 * time.Hour)
		}
		return next, nil
	case "weekly":
		hour, minute, err := parseTimeOfDay(sched.TimeOfDay)
		if err != nil {
			return time.Time{}, err
		}
		weekday, err := parseWeekday(sched.DayOfWeek)
		if err != nil {
			return time.Time{}, err
		}
		daysAhead := (int(weekday) - int(now.Weekday()) + 7) % 7
		nextDate := now.AddDate(0, 0, daysAhead)
		next := time.Date(nextDate.Year(), nextDate.Month(), nextDate.Day(), hour, minute, 0, 0, time.UTC)
		if !next.After(now) {
			nextDate = nextDate.AddDate(0, 0, 7)
			next = time.Date(nextDate.Year(), nextDate.Month(), nextDate.Day(), hour, minute, 0, 0, time.UTC)
		}
		return next, nil
	default:
		return time.Time{}, fmt.Errorf("unsupported frequency %q", sched.Frequency)
	}
}

func (s *backupService) resolveBackupPath(name string) (string, error) {
	if name == "" {
		return "", errors.New("missing backup name")
	}
	base := filepath.Base(name)
	if base != name {
		return "", errors.New("invalid backup name")
	}
	if strings.EqualFold(base, legacyScheduleFilename) {
		return "", errors.New("reserved backup name")
	}
	path := filepath.Join(s.dir, base)
	if !strings.HasPrefix(path, s.dir) {
		return "", errors.New("invalid backup path")
	}
	return path, nil
}

func cloneRawMessage(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	buf := make([]byte, len(raw))
	copy(buf, raw)
	return json.RawMessage(buf)
}
