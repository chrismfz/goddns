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
	LastUpdate time.Time
	Disabled   bool
}

type Store struct{ db *sql.DB }

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;`); err != nil {
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
		disabled    INTEGER NOT NULL DEFAULT 0
	);`
	if _, err := db.Exec(schema); err != nil {
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
	var ts int64
	var dis int
	err := row.Scan(&r.ID, &r.FQDN, &r.Zone, &r.TTL, &r.TokenHash, &r.LastIP, &ts, &dis)
	if err != nil {
		return Record{}, err
	}
	r.LastUpdate = time.Unix(ts, 0)
	r.Disabled = dis != 0
	return r, nil
}

const cols = `id, fqdn, zone, ttl, token_hash, last_ip, last_update, disabled`

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

func (s *Store) MarkUpdated(id int64, ip string) error {
	_, err := s.db.Exec(`UPDATE records SET last_ip=?, last_update=? WHERE id=?`,
		ip, time.Now().Unix(), id)
	return err
}

func (r Record) String() string {
	last := "never"
	if !r.LastUpdate.IsZero() && r.LastUpdate.Unix() > 0 {
		last = r.LastUpdate.Format(time.RFC3339)
	}
	state := "enabled"
	if r.Disabled {
		state = "disabled"
	}
	return fmt.Sprintf("#%d %-30s zone=%-20s ttl=%-4d last=%-15s (%s) %s",
		r.ID, r.FQDN, r.Zone, r.TTL, r.LastIP, last, state)
}
