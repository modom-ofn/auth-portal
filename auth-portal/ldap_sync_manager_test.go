package main

import (
	"testing"
	"time"
)

func TestLDAPSyncManagerRefreshScheduleLockedTracksConfigChanges(t *testing.T) {
	manager := &ldapSyncManager{}
	now := time.Date(2026, time.March, 13, 9, 0, 0, 0, time.UTC)

	cfg := LDAPSyncConfig{
		ScheduleEnabled:   true,
		ScheduleFrequency: "daily",
		ScheduleTimeOfDay: "10:15",
		ScheduleDayOfWeek: "friday",
		ScheduleMinute:    15,
	}

	manager.refreshScheduleLocked(cfg, now)
	first := manager.nextRun
	if first.IsZero() {
		t.Fatal("expected first nextRun to be calculated")
	}

	manager.refreshScheduleLocked(cfg, now.Add(30*time.Minute))
	if !manager.nextRun.Equal(first) {
		t.Fatalf("expected unchanged schedule to preserve cached nextRun, got %v want %v", manager.nextRun, first)
	}

	cfg.ScheduleTimeOfDay = "11:45"
	manager.refreshScheduleLocked(cfg, now.Add(30*time.Minute))
	if !manager.nextRun.After(first) {
		t.Fatalf("expected changed schedule to recalculate nextRun, got %v after %v", manager.nextRun, first)
	}
}

func TestLDAPSyncManagerRefreshScheduleLockedDisablesNextRun(t *testing.T) {
	manager := &ldapSyncManager{}
	now := time.Date(2026, time.March, 13, 9, 0, 0, 0, time.UTC)

	cfg := LDAPSyncConfig{
		ScheduleEnabled:   true,
		ScheduleFrequency: "hourly",
		ScheduleMinute:    15,
	}
	manager.refreshScheduleLocked(cfg, now)
	if manager.nextRun.IsZero() {
		t.Fatal("expected nextRun to be set for enabled schedule")
	}

	cfg.ScheduleEnabled = false
	manager.refreshScheduleLocked(cfg, now)
	if !manager.nextRun.IsZero() {
		t.Fatalf("expected nextRun to clear when disabled, got %v", manager.nextRun)
	}
}
