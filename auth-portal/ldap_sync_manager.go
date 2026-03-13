package main

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"auth-portal/ldapsync"
)

type ldapSyncRunRecord struct {
	ID              int64     `json:"id"`
	TriggerType     string    `json:"triggerType"`
	TriggeredBy     string    `json:"triggeredBy,omitempty"`
	StartedAt       time.Time `json:"startedAt"`
	FinishedAt      time.Time `json:"finishedAt"`
	Success         bool      `json:"success"`
	UsersConsidered int       `json:"usersConsidered"`
	EntriesAdded    int       `json:"entriesAdded"`
	EntriesUpdated  int       `json:"entriesUpdated"`
	EntriesDeleted  int       `json:"entriesDeleted"`
	FailedEntries   int       `json:"failedEntries"`
	Summary         string    `json:"summary,omitempty"`
	ErrorMessage    string    `json:"errorMessage,omitempty"`
}

type ldapSyncStatusView struct {
	Running       bool               `json:"running"`
	TriggeredBy   string             `json:"triggeredBy,omitempty"`
	StartedAt     *time.Time         `json:"startedAt,omitempty"`
	FinishedAt    *time.Time         `json:"finishedAt,omitempty"`
	LastSuccessAt *time.Time         `json:"lastSuccessAt,omitempty"`
	LastError     string             `json:"lastError,omitempty"`
	LastResult    ldapsync.Result    `json:"lastResult"`
	NextRun       *time.Time         `json:"nextRun,omitempty"`
	LastRun       *ldapSyncRunRecord `json:"lastRun,omitempty"`
}

type ldapSyncManager struct {
	db      *sql.DB
	service *ldapsync.Service

	mu          sync.Mutex
	scheduleKey string
	nextRun     time.Time

	stopCh  chan struct{}
	stopped chan struct{}
}

func newLDAPSyncManager(db *sql.DB, service *ldapsync.Service) (*ldapSyncManager, error) {
	if db == nil {
		return nil, errors.New("ldap sync manager requires db")
	}
	if service == nil {
		return nil, errors.New("ldap sync manager requires service")
	}
	mgr := &ldapSyncManager{
		db:      db,
		service: service,
		stopCh:  make(chan struct{}),
		stopped: make(chan struct{}),
	}
	mgr.refreshSchedule(time.Now().UTC())
	go mgr.loop()
	return mgr, nil
}

func (m *ldapSyncManager) Close() {
	select {
	case <-m.stopCh:
		return
	default:
		close(m.stopCh)
		<-m.stopped
	}
}

func (m *ldapSyncManager) loop() {
	defer close(m.stopped)
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.maybeRunScheduled()
		case <-m.stopCh:
			return
		}
	}
}

func (m *ldapSyncManager) maybeRunScheduled() {
	now := time.Now().UTC()
	cfg := currentRuntimeConfig().LDAPSync
	nextRun := m.refreshSchedule(now)
	if !cfg.ScheduleEnabled {
		return
	}
	if nextRun.IsZero() || now.Before(nextRun) {
		return
	}
	if _, _, err := m.Run(context.Background(), "system", "scheduled"); err != nil {
		log.Printf("LDAP sync scheduled run failed: %v", err)
		m.reschedule(cfg, now.Add(5*time.Minute))
	}
}

func (m *ldapSyncManager) Run(ctx context.Context, actor, triggerType string) (ldapsync.Result, ldapSyncStatusView, error) {
	cfg := currentRuntimeConfig().LDAPSync
	startedAt := time.Now().UTC()
	result, err := m.service.Run(ctx, ldapsync.Config{
		LDAPHost:           cfg.LDAPHost,
		LDAPAdminDN:        cfg.LDAPAdminDN,
		LDAPAdminPassword:  cfg.LDAPAdminPassword,
		BaseDN:             cfg.BaseDN,
		LDAPStartTLS:       cfg.LDAPStartTLS,
		DeleteStaleEntries: cfg.DeleteStaleEntries,
	}, actor)
	finishedAt := time.Now().UTC()
	if recordErr := m.recordRun(startedAt, finishedAt, actor, triggerType, result, err); recordErr != nil {
		log.Printf("LDAP sync run record failed: %v", recordErr)
	}
	if strings.EqualFold(strings.TrimSpace(triggerType), "scheduled") {
		cfg := currentRuntimeConfig().LDAPSync
		if err != nil {
			m.reschedule(cfg, finishedAt.Add(5*time.Minute))
		} else {
			m.reschedule(cfg, finishedAt)
		}
	}
	status, statusErr := m.Status(10)
	if statusErr != nil {
		return result, ldapSyncStatusView{}, err
	}
	return result, status, err
}

func (m *ldapSyncManager) recordRun(startedAt, finishedAt time.Time, actor, triggerType string, result ldapsync.Result, runErr error) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	summary := strings.TrimSpace(result.Summary)
	errMsg := ""
	if runErr != nil {
		errMsg = strings.TrimSpace(runErr.Error())
		if summary == "" {
			summary = errMsg
		}
	}
	_, err := m.db.ExecContext(ctx, `
INSERT INTO ldap_sync_runs (
  trigger_type, triggered_by, started_at, finished_at, success,
  users_considered, entries_added, entries_updated, entries_deleted, failed_entries, summary, error_message
)
VALUES ($1, NULLIF($2, ''), $3, $4, $5, $6, $7, $8, $9, $10, NULLIF($11, ''), NULLIF($12, ''))
`, strings.TrimSpace(firstNonEmpty(triggerType, "manual")), strings.TrimSpace(actor), startedAt, finishedAt, runErr == nil, result.UsersConsidered, result.EntriesAdded, result.EntriesUpdated, result.EntriesDeleted, result.FailedEntries, summary, errMsg)
	return err
}

func (m *ldapSyncManager) ListRuns(limit int) ([]ldapSyncRunRecord, error) {
	if limit <= 0 {
		limit = 10
	}
	if limit > 100 {
		limit = 100
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := m.db.QueryContext(ctx, `
SELECT id, trigger_type, triggered_by, started_at, finished_at, success,
       users_considered, entries_added, entries_updated, entries_deleted, failed_entries, summary, error_message
  FROM ldap_sync_runs
 ORDER BY started_at DESC, id DESC
 LIMIT $1
`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var runs []ldapSyncRunRecord
	for rows.Next() {
		var (
			run         ldapSyncRunRecord
			triggeredBy sql.NullString
			summary     sql.NullString
			errorMsg    sql.NullString
		)
		if err := rows.Scan(
			&run.ID,
			&run.TriggerType,
			&triggeredBy,
			&run.StartedAt,
			&run.FinishedAt,
			&run.Success,
			&run.UsersConsidered,
			&run.EntriesAdded,
			&run.EntriesUpdated,
			&run.EntriesDeleted,
			&run.FailedEntries,
			&summary,
			&errorMsg,
		); err != nil {
			return nil, err
		}
		if triggeredBy.Valid {
			run.TriggeredBy = strings.TrimSpace(triggeredBy.String)
		}
		if summary.Valid {
			run.Summary = strings.TrimSpace(summary.String)
		}
		if errorMsg.Valid {
			run.ErrorMessage = strings.TrimSpace(errorMsg.String)
		}
		run.StartedAt = run.StartedAt.UTC()
		run.FinishedAt = run.FinishedAt.UTC()
		runs = append(runs, run)
	}
	return runs, rows.Err()
}

func (m *ldapSyncManager) Status(runLimit int) (ldapSyncStatusView, error) {
	live := m.service.Status()
	status := ldapSyncStatusView{
		Running:       live.Running,
		TriggeredBy:   live.TriggeredBy,
		StartedAt:     cloneStatusTime(live.StartedAt),
		FinishedAt:    cloneStatusTime(live.FinishedAt),
		LastSuccessAt: cloneStatusTime(live.LastSuccessAt),
		LastError:     strings.TrimSpace(live.LastError),
		LastResult:    live.LastResult,
	}
	nextRun := m.refreshSchedule(time.Now().UTC())
	if !nextRun.IsZero() {
		status.NextRun = cloneStatusTime(&nextRun)
	}
	runs, err := m.ListRuns(runLimit)
	if err != nil {
		return status, err
	}
	if len(runs) > 0 {
		lastRun := runs[0]
		status.LastRun = &lastRun
		if !live.Running && status.LastResult.Summary == "" {
			status.LastResult = ldapsync.Result{
				UsersConsidered: lastRun.UsersConsidered,
				EntriesAdded:    lastRun.EntriesAdded,
				EntriesUpdated:  lastRun.EntriesUpdated,
				EntriesDeleted:  lastRun.EntriesDeleted,
				FailedEntries:   lastRun.FailedEntries,
				Summary:         lastRun.Summary,
			}
			status.FinishedAt = cloneStatusTime(&lastRun.FinishedAt)
			if lastRun.Success {
				status.LastSuccessAt = cloneStatusTime(&lastRun.FinishedAt)
			} else if status.LastError == "" {
				status.LastError = lastRun.ErrorMessage
			}
		}
	}
	return status, nil
}

func (m *ldapSyncManager) refreshSchedule(now time.Time) time.Time {
	cfg := currentRuntimeConfig().LDAPSync
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refreshScheduleLocked(cfg, now)
	return m.nextRun
}

func (m *ldapSyncManager) reschedule(cfg LDAPSyncConfig, from time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.scheduleKey = ldapSyncScheduleKey(cfg)
	nextRun, err := computeLDAPSyncNextRun(cfg, from)
	if err != nil {
		log.Printf("LDAP sync schedule compute error: %v", err)
		m.nextRun = time.Time{}
		return
	}
	m.nextRun = nextRun
}

func (m *ldapSyncManager) refreshScheduleLocked(cfg LDAPSyncConfig, now time.Time) {
	scheduleKey := ldapSyncScheduleKey(cfg)
	if !cfg.ScheduleEnabled {
		m.scheduleKey = scheduleKey
		m.nextRun = time.Time{}
		return
	}
	if m.scheduleKey == scheduleKey && !m.nextRun.IsZero() {
		return
	}
	m.scheduleKey = scheduleKey
	nextRun, err := computeLDAPSyncNextRun(cfg, now)
	if err != nil {
		log.Printf("LDAP sync schedule compute error: %v", err)
		m.nextRun = time.Time{}
		return
	}
	m.nextRun = nextRun
}

func ldapSyncScheduleKey(cfg LDAPSyncConfig) string {
	return strings.Join([]string{
		strconv.FormatBool(cfg.ScheduleEnabled),
		strings.ToLower(strings.TrimSpace(cfg.ScheduleFrequency)),
		strings.TrimSpace(cfg.ScheduleTimeOfDay),
		strings.ToLower(strings.TrimSpace(cfg.ScheduleDayOfWeek)),
		strconv.Itoa(cfg.ScheduleMinute),
	}, "|")
}

func computeLDAPSyncNextRun(cfg LDAPSyncConfig, from time.Time) (time.Time, error) {
	if !cfg.ScheduleEnabled {
		return time.Time{}, nil
	}
	sched := backupSchedule{
		Enabled:   true,
		Frequency: strings.ToLower(strings.TrimSpace(cfg.ScheduleFrequency)),
		TimeOfDay: strings.TrimSpace(cfg.ScheduleTimeOfDay),
		DayOfWeek: strings.ToLower(strings.TrimSpace(cfg.ScheduleDayOfWeek)),
		Minute:    cfg.ScheduleMinute,
	}
	normalized := normalizeLDAPSyncScheduleFields(sched)
	return computeNextRun(normalized, from)
}

func normalizeLDAPSyncScheduleFields(sched backupSchedule) backupSchedule {
	if sched.Frequency == "" {
		sched.Frequency = "daily"
	}
	if sched.Frequency == "hourly" {
		if sched.Minute < 0 || sched.Minute > 59 {
			sched.Minute = 15
		}
		sched.TimeOfDay = ""
		sched.DayOfWeek = ""
		return sched
	}
	if strings.TrimSpace(sched.TimeOfDay) == "" {
		sched.TimeOfDay = "02:15"
	}
	if strings.TrimSpace(sched.DayOfWeek) == "" {
		sched.DayOfWeek = "sunday"
	}
	sched.Minute = 0
	return sched
}

func cloneStatusTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copied := value.UTC()
	return &copied
}

var ldapSyncManagerMu sync.RWMutex

func currentLDAPSyncManager() *ldapSyncManager {
	ldapSyncManagerMu.RLock()
	defer ldapSyncManagerMu.RUnlock()
	return ldapSyncMgr
}

func setLDAPSyncManager(manager *ldapSyncManager) {
	ldapSyncManagerMu.Lock()
	defer ldapSyncManagerMu.Unlock()
	ldapSyncMgr = manager
}
