package store

import (
	"database/sql"
	"strings"
	"time"
)

// Snapshot is one captured state of a zone (its canonical record set at a
// given SOA serial). Content is the sorted zone-file text.
type Snapshot struct {
	ID      int64
	Zone    string
	Serial  uint32
	TakenAt time.Time
	Content string
}

// snapZone normalises a zone name for storage (lowercase, no trailing dot) so
// lookups match regardless of how the caller spelled it.
func snapZone(zone string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
}

// SnapshotLatest returns the most recent snapshot for zone (ok=false if none).
func (s *Store) SnapshotLatest(zone string) (Snapshot, bool, error) {
	row := s.db.QueryRow(
		`SELECT id, zone, serial, taken_at, content FROM snapshots
		 WHERE zone=? ORDER BY id DESC LIMIT 1`, snapZone(zone))
	return scanSnapshot(row)
}

// SnapshotByID returns a snapshot by id (ok=false if not found).
func (s *Store) SnapshotByID(id int64) (Snapshot, bool, error) {
	row := s.db.QueryRow(
		`SELECT id, zone, serial, taken_at, content FROM snapshots WHERE id=?`, id)
	return scanSnapshot(row)
}

// SnapshotPut stores a new snapshot for zone and prunes the zone's history to
// at most keep rows (keep<=0 means unlimited). The insert and prune run in one
// transaction so a concurrent reader never sees keep+1 rows and the write lock
// is taken once. Returns the new row id.
func (s *Store) SnapshotPut(zone string, serial uint32, content string, keep int) (int64, error) {
	z := snapZone(zone)
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	res, err := tx.Exec(
		`INSERT INTO snapshots (zone, serial, taken_at, content) VALUES (?,?,?,?)`,
		z, serial, time.Now().Unix(), content)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	if keep > 0 {
		// Delete everything older than the newest `keep` rows for this zone.
		if _, err := tx.Exec(
			`DELETE FROM snapshots WHERE zone=? AND id NOT IN
			 (SELECT id FROM snapshots WHERE zone=? ORDER BY id DESC LIMIT ?)`,
			z, z, keep); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return id, nil
}

// SnapshotList returns snapshots for zone, newest first, up to limit (limit<=0
// = all). Content is omitted (use SnapshotByID) so listing stays cheap.
func (s *Store) SnapshotList(zone string, limit int) ([]Snapshot, error) {
	q := `SELECT id, zone, serial, taken_at FROM snapshots WHERE zone=? ORDER BY id DESC`
	args := []any{snapZone(zone)}
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Snapshot
	for rows.Next() {
		var sn Snapshot
		var ts int64
		if err := rows.Scan(&sn.ID, &sn.Zone, &sn.Serial, &ts); err != nil {
			return nil, err
		}
		sn.TakenAt = time.Unix(ts, 0)
		out = append(out, sn)
	}
	return out, rows.Err()
}

func scanSnapshot(row *sql.Row) (Snapshot, bool, error) {
	var sn Snapshot
	var ts int64
	switch err := row.Scan(&sn.ID, &sn.Zone, &sn.Serial, &ts, &sn.Content); err {
	case nil:
		sn.TakenAt = time.Unix(ts, 0)
		return sn, true, nil
	case sql.ErrNoRows:
		return Snapshot{}, false, nil
	default:
		return Snapshot{}, false, err
	}
}
