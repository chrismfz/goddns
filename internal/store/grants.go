package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

// ErrNoGrant is returned when a (user, zone) grant does not exist.
var ErrNoGrant = errors.New("no such grant")

// A zone grant lets a "user"-role login manage exactly one zone (not its
// subzones: a more specific zone is its own grant). Zone names are stored
// lowercase without the trailing dot; the service normalizes them.
func migrateGrants(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS zone_grants (
		user       TEXT NOT NULL,
		zone       TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		PRIMARY KEY (user, zone)
	);`)
	return err
}

// GrantAdd grants zone to user. Granting twice is a no-op.
func (s *Store) GrantAdd(user, zone string) error {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO zone_grants (user, zone, created_at) VALUES (?, ?, ?)`,
		user, normGrantZone(zone), time.Now().Unix())
	return err
}

// GrantDel revokes one grant (ErrNoGrant if it wasn't there).
func (s *Store) GrantDel(user, zone string) error {
	res, err := s.db.Exec(`DELETE FROM zone_grants WHERE user = ? AND zone = ?`, user, normGrantZone(zone))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNoGrant
	}
	return nil
}

// GrantsDelZone drops every grant on zone (the zone was deleted).
func (s *Store) GrantsDelZone(zone string) error {
	_, err := s.db.Exec(`DELETE FROM zone_grants WHERE zone = ?`, normGrantZone(zone))
	return err
}

// GrantsFor returns the zones granted to user, sorted.
func (s *Store) GrantsFor(user string) ([]string, error) {
	rows, err := s.db.Query(`SELECT zone FROM zone_grants WHERE user = ? ORDER BY zone`, user)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var z string
		if err := rows.Scan(&z); err != nil {
			return nil, err
		}
		out = append(out, z)
	}
	return out, rows.Err()
}

// GrantsAll returns every grant as user → sorted zones.
func (s *Store) GrantsAll() (map[string][]string, error) {
	rows, err := s.db.Query(`SELECT user, zone FROM zone_grants ORDER BY user, zone`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var u, z string
		if err := rows.Scan(&u, &z); err != nil {
			return nil, err
		}
		out[u] = append(out[u], z)
	}
	return out, rows.Err()
}

// normGrantZone is the stored form of a zone name (callers normally pass it
// normalized already; this keeps a direct store caller from storing a
// second spelling).
func normGrantZone(z string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(z)), ".")
}
