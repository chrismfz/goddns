package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

// APIToken is a machine-API credential. It belongs to one login (User) and
// acts as that login — never with more than its role and grants — further
// narrowed by Scopes and, optionally, source CIDRs and an expiry. Only the
// SHA-256 of the token is stored.
type APIToken struct {
	ID        int64
	Name      string // unique per user, for listing/audit (never secret)
	User      string
	TokenHash string
	Scopes    []string
	AllowNets []string  // source CIDRs; empty = anywhere
	ExpiresAt time.Time // zero = never
	CreatedAt time.Time
	LastUsed  time.Time // zero = never used
}

// ErrNoAPIToken is returned when a token (id or hash) does not exist.
var ErrNoAPIToken = errors.New("no such API token")

// APITokenPrefix marks goddns API tokens, so a leaked one is recognisable
// (secret scanners, logs) and can't be confused with a DDNS token.
const APITokenPrefix = "gdapi_"

func migrateAPITokens(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS api_tokens (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		name        TEXT NOT NULL,
		user        TEXT NOT NULL,
		token_hash  TEXT NOT NULL UNIQUE,
		scopes      TEXT NOT NULL,
		allow_nets  TEXT NOT NULL DEFAULT '',
		expires_at  INTEGER NOT NULL DEFAULT 0,
		created_at  INTEGER NOT NULL,
		last_used   INTEGER NOT NULL DEFAULT 0,
		UNIQUE (user, name)
	);`)
	return err
}

const apiCols = `id, name, user, token_hash, scopes, allow_nets, expires_at, created_at, last_used`

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

func unixOrZero(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(n, 0)
}

func scanAPIToken(row interface{ Scan(...any) error }) (APIToken, error) {
	var t APIToken
	var scopes, nets string
	var exp, created, used int64
	if err := row.Scan(&t.ID, &t.Name, &t.User, &t.TokenHash, &scopes, &nets, &exp, &created, &used); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return APIToken{}, ErrNoAPIToken
		}
		return APIToken{}, err
	}
	t.Scopes, t.AllowNets = splitList(scopes), splitList(nets)
	t.ExpiresAt, t.CreatedAt, t.LastUsed = unixOrZero(exp), time.Unix(created, 0), unixOrZero(used)
	return t, nil
}

// APITokenAdd stores a new token and returns it with its plaintext — the
// only time the plaintext exists.
func (s *Store) APITokenAdd(user, name string, scopes, allowNets []string, expires time.Time) (APIToken, string, error) {
	tok := APITokenPrefix + newToken()
	t := APIToken{Name: name, User: user, TokenHash: hashToken(tok), Scopes: scopes, AllowNets: allowNets,
		ExpiresAt: expires, CreatedAt: time.Now()}
	var exp int64
	if !expires.IsZero() {
		exp = expires.Unix()
	}
	res, err := s.db.Exec(`INSERT INTO api_tokens (name, user, token_hash, scopes, allow_nets, expires_at, created_at) VALUES (?,?,?,?,?,?,?)`,
		name, user, t.TokenHash, strings.Join(scopes, ","), strings.Join(allowNets, ","), exp, t.CreatedAt.Unix())
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return APIToken{}, "", errors.New("an API token with that name already exists for this user")
		}
		return APIToken{}, "", err
	}
	t.ID, _ = res.LastInsertId()
	return t, tok, nil
}

// APITokenLookup finds a token by its plaintext (matched on the hash).
func (s *Store) APITokenLookup(tok string) (APIToken, error) {
	return scanAPIToken(s.db.QueryRow(`SELECT `+apiCols+` FROM api_tokens WHERE token_hash = ?`, hashToken(tok)))
}

// APITokenGet returns one token by id.
func (s *Store) APITokenGet(id int64) (APIToken, error) {
	return scanAPIToken(s.db.QueryRow(`SELECT `+apiCols+` FROM api_tokens WHERE id = ?`, id))
}

// APITokenList returns user's tokens, or every token when user is "".
func (s *Store) APITokenList(user string) ([]APIToken, error) {
	q, args := `SELECT `+apiCols+` FROM api_tokens ORDER BY user, name`, []any{}
	if user != "" {
		q, args = `SELECT `+apiCols+` FROM api_tokens WHERE user = ? ORDER BY name`, []any{user}
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIToken
	for rows.Next() {
		t, err := scanAPIToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// APITokenDel revokes a token.
func (s *Store) APITokenDel(id int64) error {
	res, err := s.db.Exec(`DELETE FROM api_tokens WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNoAPIToken
	}
	return nil
}

// APITokenTouch records a use (best-effort, at most once a minute per token
// so a busy client doesn't turn every request into a write).
func (s *Store) APITokenTouch(id int64, now time.Time) error {
	_, err := s.db.Exec(`UPDATE api_tokens SET last_used = ? WHERE id = ? AND last_used < ?`,
		now.Unix(), id, now.Add(-time.Minute).Unix())
	return err
}
