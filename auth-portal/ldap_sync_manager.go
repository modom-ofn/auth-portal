package main

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"
)

type ldapSyncManager struct {
	mu            sync.Mutex
	debounce      time.Duration
	onChange      bool
	scheduled     bool
	interval      time.Duration
	nextScheduled time.Time
	changeTimer   *time.Timer
	scheduleTimer *time.Timer
}

var ldapScheduler = newLDAPSyncManager()

func newLDAPSyncManager() *ldapSyncManager {
	return &ldapSyncManager{
		debounce: defaultLDAPAutoDebounce,
	}
}

func (m *ldapSyncManager) Configure(cfg LDAPConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()

	debounce := parseDurationOr(strings.TrimSpace(cfg.AutoSyncDebounce), defaultLDAPAutoDebounce)
	if debounce < minLDAPAutoDebounce {
		debounce = minLDAPAutoDebounce
	}
	m.debounce = debounce
	m.onChange = cfg.Enabled && cfg.AutoSyncOnChange
	if !m.onChange && m.changeTimer != nil {
		m.changeTimer.Stop()
		m.changeTimer = nil
	}

	m.interval = 0
	m.scheduled = false
	if cfg.Enabled && cfg.ScheduledSyncEnabled {
		interval := parseDurationOr(strings.TrimSpace(cfg.ScheduledSyncInterval), defaultLDAPScheduledEvery)
		if interval < minLDAPScheduledEvery {
			interval = minLDAPScheduledEvery
		}
		m.interval = interval
		m.scheduled = interval > 0
	}

	m.resetScheduledLocked()
	m.updateScheduleStateLocked()
}

func (m *ldapSyncManager) TriggerChange(reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.onChange {
		return
	}

	if m.changeTimer != nil {
		m.changeTimer.Stop()
	}

	m.changeTimer = time.AfterFunc(m.debounce, func() {
		trigger := strings.TrimSpace(reason)
		if trigger == "" {
			trigger = "role/user change"
		}
		m.runSync(trigger)
	})
}

func (m *ldapSyncManager) resetScheduledLocked() {
	if m.scheduleTimer != nil {
		m.scheduleTimer.Stop()
		m.scheduleTimer = nil
	}
	m.nextScheduled = time.Time{}

	if !m.scheduled || m.interval <= 0 {
		return
	}

	m.scheduleTimer = time.AfterFunc(m.interval, func() {
		m.runSync("scheduled")
	})
	m.nextScheduled = time.Now().UTC().Add(m.interval)
}

func (m *ldapSyncManager) afterRun() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.scheduled && m.interval > 0 {
		m.resetScheduledLocked()
	} else {
		m.updateScheduleStateLocked()
	}
}

func (m *ldapSyncManager) updateScheduleStateLocked() {
	ldapUpdateScheduleState(m.onChange, m.scheduled, m.debounce, m.interval, m.nextScheduled)
}

func (m *ldapSyncManager) runSync(trigger string) {
	cfg := currentRuntimeConfig().LDAP
	if !cfg.Enabled {
		return
	}

	if !ldapMarkRunning() {
		requeued := false
		m.mu.Lock()
		if trigger == "scheduled" && m.scheduled && m.interval > 0 {
			m.resetScheduledLocked()
			m.updateScheduleStateLocked()
			requeued = true
		} else if m.onChange {
			if m.changeTimer != nil {
				m.changeTimer.Stop()
			}
			m.changeTimer = time.AfterFunc(m.debounce, func() {
				m.runSync(trigger)
			})
			m.updateScheduleStateLocked()
			requeued = true
		}
		m.mu.Unlock()
		if requeued {
			log.Printf("ldap sync skipped (%s): already running; queued another run", trigger)
		} else {
			log.Printf("ldap sync skipped (%s): already running", trigger)
		}
		return
	}

	log.Printf("starting ldap sync (trigger=%s)", trigger)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	result := runLDAPSync(ctx, cfg)
	ldapFinishRun(result)

	m.afterRun()
}
