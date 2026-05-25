package backupsv

import (
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"
)

type recoveryWindowBackup struct {
	name      string
	path      string
	startedAt time.Time
	beginWAL  string
}

func chooseRecoveryWindowAnchor(
	backups []recoveryWindowBackup,
	recoveryWindow time.Duration,
	minimumBackups int,
	now time.Time,
) *recoveryWindowBackup {
	if now.IsZero() {
		now = time.Now()
	}

	if len(backups) == 0 {
		return nil
	}

	if minimumBackups <= 0 {
		minimumBackups = 1
	}

	sorted := slices.Clone(backups)

	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].startedAt.Before(sorted[j].startedAt)
	})

	windowStart := now.Add(-recoveryWindow)

	anchorIdx := -1

	// Barman-like recovery window:
	// choose newest backup that started before or at window start.
	for i := range sorted {
		if sorted[i].startedAt.After(windowStart) {
			continue
		}

		anchorIdx = i
	}

	// If all backups are newer than the window start,
	// keep the oldest backup as the safest available anchor.
	if anchorIdx == -1 {
		anchorIdx = 0
	}

	// Safety: keep at least minimumBackups newest backups.
	keptCount := len(sorted) - anchorIdx
	if keptCount < minimumBackups {
		anchorIdx = len(sorted) - minimumBackups
		if anchorIdx < 0 {
			anchorIdx = 0
		}
	}

	anchor := sorted[anchorIdx]
	return &anchor
}

func backupsOlderThanAnchor(backups []recoveryWindowBackup, anchor *recoveryWindowBackup) []string {
	if anchor == nil {
		return nil
	}

	toDelete := make([]string, 0)

	for _, b := range backups {
		if b.startedAt.Before(anchor.startedAt) {
			toDelete = append(toDelete, b.name)
		}
	}

	slices.Sort(toDelete)
	return toDelete
}

func normalizeWALFilename(path string) (name string, history, ok bool) {
	base := filepath.Base(path)

	// ListInfoRaw returns backend/raw paths, so transformation suffixes and the
	// checksum separator ("--{sha256hex}") may still be present. Strip them all
	// to recover the underlying PostgreSQL WAL filename.
	for {
		old := base

		base = strings.TrimSuffix(base, ".gz")
		base = strings.TrimSuffix(base, ".zst")
		base = strings.TrimSuffix(base, ".lz4")
		base = strings.TrimSuffix(base, ".aes")

		if old == base {
			break
		}
	}

	// Strip "--{sha256hex}" checksum suffix if present.
	if idx := strings.LastIndex(base, "--"); idx >= 0 {
		base = base[:idx]
	}

	if strings.HasSuffix(base, ".history") {
		return base, true, true
	}

	if len(base) != 24 {
		return "", false, false
	}

	for _, ch := range base {
		isOk := (ch >= '0' && ch <= '9') ||
			(ch >= 'A' && ch <= 'F') ||
			(ch >= 'a' && ch <= 'f')
		if !isOk {
			return "", false, false
		}
	}

	return strings.ToUpper(base), false, true
}

func walBefore(name, boundary string) bool {
	name = strings.ToUpper(strings.TrimSpace(name))
	boundary = strings.ToUpper(strings.TrimSpace(boundary))

	return name != "" && boundary != "" && name < boundary
}
