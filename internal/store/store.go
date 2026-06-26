// Package store is the SQLite-backed token store: one bearer token
// authorises updates to exactly one FQDN in one zone. Only the SHA-256
// hash of a token is ever persisted.
package store

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Record is a token→FQDN binding.
type Record struct {
	ID         int64
	FQDN       string // home.myip.gr.
	Zone       string // myip.gr.
	TTL        uint32
	TokenHash  string // sha256 hex of the bearer token
	LastIP     string
	LastUpdate time.Time // when the IP last CHANGED (a DNS write happened)
	LastSeen   time.Time // when the client last checked in (incl. nochg polls)
	Disabled   bool
}

type Store struct{ db *sql.DB }

func Open(path string) (*Store, error) {
	// Pragmas go in the DSN so they apply to EVERY pooled connection —
	// a bare `PRAGMA` Exec only configures whichever connection the pool
	// happens to hand out, and concurrent CLI+server access would then
	// hit "database is locked" on the unconfigured ones.
	db, err := sql.Open("sqlite",
		"file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	schema := `CREATE TABLE IF NOT EXISTS records (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		fqdn        TEXT NOT NULL UNIQUE,
		zone        TEXT NOT NULL,
		ttl         INTEGER NOT NULL DEFAULT 60,
		token_hash  TEXT NOT NULL UNIQUE,
		last_ip     TEXT NOT NULL DEFAULT '',
		last_update INTEGER NOT NULL DEFAULT 0,
		last_seen   INTEGER NOT NULL DEFAULT 0,
		disabled    INTEGER NOT NULL DEFAULT 0
	);`
	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}
	// Migrate DBs created before last_seen existed. ADD COLUMN errors with
	// "duplicate column name" once the column is present, so the column-already-
	// exists case is the expected no-op, not a failure.
	if _, err := db.Exec(`ALTER TABLE records ADD COLUMN last_seen INTEGER NOT NULL DEFAULT 0`); err != nil &&
		!strings.Contains(err.Error(), "duplicate column name") {
		return nil, err
	}
	// Zone history snapshots (Phase 1): one row per captured zone state.
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS snapshots (
		id        INTEGER PRIMARY KEY AUTOINCREMENT,
		zone      TEXT NOT NULL,
		serial    INTEGER NOT NULL,
		taken_at  INTEGER NOT NULL,
		content   TEXT NOT NULL
	);`); err != nil {
		return nil, err
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_snap_zone ON snapshots(zone, id DESC);`); err != nil {
		return nil, err
	}
	// Persisted proxy traffic: one row per host per UTC day, accumulated from
	// the in-memory counters by the serve loop's periodic flush. Survives
	// restarts; monthly totals are derived by summing the days.
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS proxy_traffic (
		host       TEXT NOT NULL,
		day        TEXT NOT NULL,
		requests   INTEGER NOT NULL DEFAULT 0,
		bytes_in   INTEGER NOT NULL DEFAULT 0,
		bytes_out  INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (host, day)
	);`); err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// FQDN lower-cases and dot-terminates a DNS name.
func FQDN(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return s
}

func hashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// newToken returns a 256-bit URL-safe token. Only its hash is stored.
func newToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

var ErrNotFound = errors.New("record not found")

// Add creates a binding and returns the plaintext token exactly once.
func (s *Store) Add(name, zone string, ttl uint32) (Record, string, error) {
	tok := newToken()
	rec := Record{FQDN: FQDN(name), Zone: FQDN(zone), TTL: ttl, TokenHash: hashToken(tok)}
	res, err := s.db.Exec(
		`INSERT INTO records (fqdn, zone, ttl, token_hash) VALUES (?,?,?,?)`,
		rec.FQDN, rec.Zone, rec.TTL, rec.TokenHash)
	if err != nil {
		return Record{}, "", err
	}
	rec.ID, _ = res.LastInsertId()
	return rec, tok, nil
}

func (s *Store) scan(row interface{ Scan(...any) error }) (Record, error) {
	var r Record
	var updTs, seenTs int64
	var dis int
	err := row.Scan(&r.ID, &r.FQDN, &r.Zone, &r.TTL, &r.TokenHash, &r.LastIP, &updTs, &seenTs, &dis)
	if err != nil {
		return Record{}, err
	}
	r.LastUpdate = time.Unix(updTs, 0)
	r.LastSeen = time.Unix(seenTs, 0)
	r.Disabled = dis != 0
	return r, nil
}

const cols = `id, fqdn, zone, ttl, token_hash, last_ip, last_update, last_seen, disabled`

// Lookup finds an enabled record by plaintext token (matched on its hash).
func (s *Store) Lookup(tok string) (Record, error) {
	row := s.db.QueryRow(`SELECT `+cols+` FROM records WHERE token_hash=? AND disabled=0`, hashToken(tok))
	r, err := s.scan(row)
	if err == sql.ErrNoRows {
		return Record{}, ErrNotFound
	}
	return r, err
}

func (s *Store) List() ([]Record, error) {
	rows, err := s.db.Query(`SELECT ` + cols + ` FROM records ORDER BY fqdn`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		r, err := s.scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) Del(name string) error {
	res, err := s.db.Exec(`DELETE FROM records WHERE fqdn=?`, FQDN(name))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Rotate issues a fresh token for an existing FQDN (the old token stops
// working immediately) and returns the new plaintext exactly once. last_ip
// and history are preserved.
func (s *Store) Rotate(name string) (Record, string, error) {
	tok := newToken()
	res, err := s.db.Exec(`UPDATE records SET token_hash=? WHERE fqdn=?`, hashToken(tok), FQDN(name))
	if err != nil {
		return Record{}, "", err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return Record{}, "", ErrNotFound
	}
	row := s.db.QueryRow(`SELECT `+cols+` FROM records WHERE fqdn=?`, FQDN(name))
	r, err := s.scan(row)
	return r, tok, err
}

// Get returns the record for an FQDN (without exposing the token).
func (s *Store) Get(name string) (Record, error) {
	row := s.db.QueryRow(`SELECT `+cols+` FROM records WHERE fqdn=?`, FQDN(name))
	r, err := s.scan(row)
	if err == sql.ErrNoRows {
		return Record{}, ErrNotFound
	}
	return r, err
}

// MarkUpdated records an IP change: it stamps both last_update (the change)
// and last_seen (a change is also a check-in).
func (s *Store) MarkUpdated(id int64, ip string) error {
	now := time.Now().Unix()
	_, err := s.db.Exec(`UPDATE records SET last_ip=?, last_update=?, last_seen=? WHERE id=?`,
		ip, now, now, id)
	return err
}

// MarkSeen records a check-in without an IP change (a nochg poll): it stamps
// last_seen only, leaving last_ip/last_update untouched. This is the liveness
// signal — proof the client is still polling even though DNS didn't change.
func (s *Store) MarkSeen(id int64) error {
	_, err := s.db.Exec(`UPDATE records SET last_seen=? WHERE id=?`, time.Now().Unix(), id)
	return err
}

// TrafficRow is one host's traffic over a period (a day "YYYY-MM-DD" or a
// month "YYYY-MM"), for the admin history view.
type TrafficRow struct {
	Host     string
	Period   string
	Requests int64
	BytesIn  int64
	BytesOut int64
}

// AddTraffic accumulates a day's traffic delta for a host (UPSERT-add). day is
// "YYYY-MM-DD". A zero delta is a no-op the caller may skip.
func (s *Store) AddTraffic(host, day string, dReq, dIn, dOut int64) error {
	_, err := s.db.Exec(
		`INSERT INTO proxy_traffic (host, day, requests, bytes_in, bytes_out) VALUES (?,?,?,?,?)
		 ON CONFLICT(host, day) DO UPDATE SET
		   requests  = requests  + excluded.requests,
		   bytes_in  = bytes_in  + excluded.bytes_in,
		   bytes_out = bytes_out + excluded.bytes_out`,
		host, day, dReq, dIn, dOut)
	return err
}

// TrafficDaily returns per-host, per-day rows for the last `days` days (most
// recent first), summing nothing — the stored granularity is already daily.
func (s *Store) TrafficDaily(days int) ([]TrafficRow, error) {
	return s.trafficQuery(`SELECT host, day, requests, bytes_in, bytes_out
		FROM proxy_traffic
		WHERE day >= date('now', ?)
		ORDER BY day DESC, host ASC`, fmt.Sprintf("-%d days", days))
}

// TrafficMonthly returns per-host, per-month totals for the last `months`
// months (most recent first), summing the daily rows.
func (s *Store) TrafficMonthly(months int) ([]TrafficRow, error) {
	return s.trafficQuery(`SELECT host, substr(day,1,7) AS m, SUM(requests), SUM(bytes_in), SUM(bytes_out)
		FROM proxy_traffic
		WHERE day >= date('now', 'start of month', ?)
		GROUP BY host, m
		ORDER BY m DESC, host ASC`, fmt.Sprintf("-%d months", months-1))
}

func (s *Store) trafficQuery(q, arg string) ([]TrafficRow, error) {
	rows, err := s.db.Query(q, arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TrafficRow
	for rows.Next() {
		var r TrafficRow
		if err := rows.Scan(&r.Host, &r.Period, &r.Requests, &r.BytesIn, &r.BytesOut); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// PruneTraffic deletes day rows older than keepDays, bounding the table.
func (s *Store) PruneTraffic(keepDays int) error {
	_, err := s.db.Exec(`DELETE FROM proxy_traffic WHERE day < date('now', ?)`,
		fmt.Sprintf("-%d days", keepDays))
	return err
}

func (r Record) String() string {
	fmtTime := func(t time.Time) string {
		if t.IsZero() || t.Unix() <= 0 {
			return "never"
		}
		return t.Format(time.RFC3339)
	}
	state := "enabled"
	if r.Disabled {
		state = "disabled"
	}
	return fmt.Sprintf("#%d %-30s zone=%-20s ttl=%-4d last=%-15s (changed %s, seen %s) %s",
		r.ID, r.FQDN, r.Zone, r.TTL, r.LastIP, fmtTime(r.LastUpdate), fmtTime(r.LastSeen), state)
}
