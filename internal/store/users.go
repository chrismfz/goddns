package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// User is an admin-UI login kept in SQLite (the [admin] users in goddns.conf
// are separate: read-only bootstrap admins). PassHash is argon2id.
type User struct {
	ID        int64
	Name      string
	PassHash  string
	Role      string // "admin" | "user" (validated by the service layer)
	Disabled  bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ErrNoUser is returned when a named user does not exist.
var ErrNoUser = errors.New("no such user")

func migrateUsers(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		name       TEXT NOT NULL UNIQUE,
		pass_hash  TEXT NOT NULL,
		role       TEXT NOT NULL,
		disabled   INTEGER NOT NULL DEFAULT 0,
		created_at INTEGER NOT NULL,
		updated_at INTEGER NOT NULL
	);`)
	return err
}

const userCols = `id, name, pass_hash, role, disabled, created_at, updated_at`

func scanUser(row interface{ Scan(...any) error }) (User, error) {
	var u User
	var dis int
	var c, up int64
	if err := row.Scan(&u.ID, &u.Name, &u.PassHash, &u.Role, &dis, &c, &up); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, ErrNoUser
		}
		return User{}, err
	}
	u.Disabled = dis != 0
	u.CreatedAt, u.UpdatedAt = time.Unix(c, 0), time.Unix(up, 0)
	return u, nil
}

// UserAdd creates a user. The name must be unique.
func (s *Store) UserAdd(name, passHash, role string) (User, error) {
	now := time.Now().Unix()
	res, err := s.db.Exec(`INSERT INTO users (name, pass_hash, role, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		name, passHash, role, now, now)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return User{}, fmt.Errorf("user %q already exists", name)
		}
		return User{}, err
	}
	id, _ := res.LastInsertId()
	return User{ID: id, Name: name, PassHash: passHash, Role: role, CreatedAt: time.Unix(now, 0), UpdatedAt: time.Unix(now, 0)}, nil
}

// UserGet returns one user by name (ErrNoUser if absent).
func (s *Store) UserGet(name string) (User, error) {
	return scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE name = ?`, name))
}

// UserList returns every user, by name.
func (s *Store) UserList() ([]User, error) {
	rows, err := s.db.Query(`SELECT ` + userCols + ` FROM users ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) userUpdate(name, set string, arg any) error {
	res, err := s.db.Exec(`UPDATE users SET `+set+` = ?, updated_at = ? WHERE name = ?`, arg, time.Now().Unix(), name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNoUser
	}
	return nil
}

// UserSetPassword replaces a user's password hash.
func (s *Store) UserSetPassword(name, passHash string) error {
	return s.userUpdate(name, "pass_hash", passHash)
}

// UserSetRole changes a user's role.
func (s *Store) UserSetRole(name, role string) error { return s.userUpdate(name, "role", role) }

// UserSetDisabled disables (true) or re-enables (false) a user.
func (s *Store) UserSetDisabled(name string, disabled bool) error {
	v := 0
	if disabled {
		v = 1
	}
	return s.userUpdate(name, "disabled", v)
}

// UserDel removes a user.
func (s *Store) UserDel(name string) error {
	res, err := s.db.Exec(`DELETE FROM users WHERE name = ?`, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNoUser
	}
	return nil
}
