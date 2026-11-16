package service

import (
	"errors"
	"regexp"
	"strings"
	"sync"

	"github.com/chrismfz/goddns/internal/auth"
	"github.com/chrismfz/goddns/internal/store"
)

// Roles. An admin may do everything; a user may log in and change their own
// password, and nothing else until zone grants exist (fail-closed: a role that
// grants nothing yet is safer than one that grants "read everything").
const (
	RoleAdmin = "admin"
	RoleUser  = "user"
)

// ErrForbidden is returned when the actor's role does not allow the call.
var ErrForbidden = errors.New("forbidden: this needs the admin role")

// IsForbidden reports whether err is (or wraps) ErrForbidden.
func IsForbidden(err error) bool { return errors.Is(err, ErrForbidden) }

func (s *Service) requireAdmin(a Actor) error {
	if a.Role != RoleAdmin {
		return ErrForbidden
	}
	return nil
}

// usernameRe: lowercase, starts with a letter or digit, at most 32 chars, and
// none of ':' (the user:hash separator), '|' (the session separator) or space.
var usernameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)

func validRole(r string) bool { return r == RoleAdmin || r == RoleUser }

// Principal is an authenticated identity.
type Principal struct {
	Name   string
	Role   string
	Config bool // a bootstrap admin from goddns.conf [admin] users (read-only here)
}

// configHash returns the bcrypt hash of a goddns.conf [admin] users entry.
func (s *Service) configHash(name string) (string, bool) {
	for _, c := range s.cfg().Admin.Users {
		u, hash, ok := strings.Cut(c, ":")
		if ok && u == name {
			return hash, true
		}
	}
	return "", false
}

// Lookup resolves a session's user to its current principal, plus a
// credential fingerprint that sessions and CSRF tokens are bound to. The
// fingerprint changes when the password or the role changes, so either one
// ends every outstanding session; a disabled or deleted user is !ok. A
// goddns.conf user wins over a database user of the same name.
func (s *Service) Lookup(name string) (p Principal, fingerprint string, ok bool) {
	if hash, ok := s.configHash(name); ok {
		return Principal{Name: name, Role: RoleAdmin, Config: true}, hash, true
	}
	u, err := s.store.UserGet(name)
	if err != nil || u.Disabled || !validRole(u.Role) {
		return Principal{}, "", false
	}
	return Principal{Name: u.Name, Role: u.Role}, "db|" + u.Role + "|" + u.PassHash, true
}

// Login verifies a name and password. An unknown, disabled or broken user
// still costs one argon2id verify, the same as a database user with a wrong
// password. (goddns.conf users are bcrypt, so their timing differs; the
// admin vhost's CIDR allowlist, Basic gate and IP throttle sit in front.)
func (s *Service) Login(name, pass string) (Principal, bool) {
	if hash, ok := s.configHash(name); ok {
		if auth.Verify(hash, pass) != nil {
			return Principal{}, false
		}
		return Principal{Name: name, Role: RoleAdmin, Config: true}, true
	}
	u, err := s.store.UserGet(name)
	if err != nil || u.Disabled || !validRole(u.Role) {
		auth.Burn(pass)
		return Principal{}, false
	}
	if auth.Verify(u.PassHash, pass) != nil {
		return Principal{}, false
	}
	return Principal{Name: u.Name, Role: u.Role}, true
}

// UserInfo is a login as the users page lists it (never the hash).
type UserInfo struct {
	Name     string
	Role     string
	Disabled bool
	Config   bool // from goddns.conf: shown, not editable here
	Shadowed bool // a database user hidden by a goddns.conf user of the same name
	Created  string
}

// Users lists every login: goddns.conf admins first, then the database users.
func (s *Service) Users(a Actor) ([]UserInfo, error) {
	if err := s.requireAdmin(a); err != nil {
		return nil, err
	}
	var out []UserInfo
	conf := map[string]bool{}
	for _, c := range s.cfg().Admin.Users {
		if u, _, ok := strings.Cut(c, ":"); ok {
			conf[u] = true
			out = append(out, UserInfo{Name: u, Role: RoleAdmin, Config: true})
		}
	}
	db, err := s.store.UserList()
	if err != nil {
		return nil, err
	}
	for _, u := range db {
		out = append(out, UserInfo{Name: u.Name, Role: u.Role, Disabled: u.Disabled, Shadowed: conf[u.Name],
			Created: u.CreatedAt.Format("2006-01-02")})
	}
	return out, nil
}

// userMu serialises the user mutations so the last-admin guard can't be
// raced by two demotions in this process. (A concurrent CLI run is a
// separate process; the guard still holds for each call on its own.)
var userMu sync.Mutex

// enabledAdmins counts the logins that can act as admin right now.
func (s *Service) enabledAdmins() (int, error) {
	n := 0
	conf := map[string]bool{}
	for _, c := range s.cfg().Admin.Users {
		if u, _, ok := strings.Cut(c, ":"); ok {
			conf[u] = true
			n++
		}
	}
	db, err := s.store.UserList()
	if err != nil {
		return 0, err
	}
	for _, u := range db {
		if u.Role == RoleAdmin && !u.Disabled && !conf[u.Name] {
			n++
		}
	}
	return n, nil
}

// dbUser loads a database user that this layer may change: not a goddns.conf
// user (those belong to the operator's file), and existing.
func (s *Service) dbUser(name string) (store.User, error) {
	if _, ok := s.configHash(name); ok {
		return store.User{}, invalid("%q is defined in goddns.conf [admin] users — change it there", name)
	}
	u, err := s.store.UserGet(name)
	if errors.Is(err, store.ErrNoUser) {
		return store.User{}, invalid("no user %q", name)
	}
	return u, err
}

// guardAdminLoss refuses a change that takes admin power away from u when
// that would leave no admin able to log in, and refuses it on yourself.
func (s *Service) guardAdminLoss(a Actor, u store.User, what string) error {
	if u.Role != RoleAdmin || u.Disabled {
		return nil
	}
	if a.User == u.Name {
		return invalid("you can't %s your own account", what)
	}
	n, err := s.enabledAdmins()
	if err != nil {
		return err
	}
	if n <= 1 {
		return invalid("%s %q would leave no admin able to log in", what, u.Name)
	}
	return nil
}

// UserAdd creates a database user with an argon2id password hash.
func (s *Service) UserAdd(a Actor, name, pass, role string) error {
	if err := s.requireAdmin(a); err != nil {
		return err
	}
	name = strings.TrimSpace(name)
	if name == "" || pass == "" || role == "" {
		return missing("name, password and role are required")
	}
	if !usernameRe.MatchString(name) {
		return invalid("username %q: use 1-32 of a-z 0-9 . _ - (starting with a letter or digit)", name)
	}
	if !validRole(role) {
		return invalid("role must be %q or %q", RoleAdmin, RoleUser)
	}
	if _, ok := s.configHash(name); ok {
		return invalid("%q is already a goddns.conf [admin] user", name)
	}
	if err := auth.CheckPolicy(pass); err != nil {
		return invalid("%v", err)
	}
	hash, err := auth.Hash(pass)
	if err != nil {
		return err
	}
	userMu.Lock()
	defer userMu.Unlock()
	if _, err := s.store.UserAdd(name, hash, role); err != nil {
		if strings.Contains(err.Error(), "already exists") {
			return invalid("%v", err)
		}
		return err
	}
	s.Audit(a, "user-add name=%s role=%s", name, role)
	return nil
}

// UserSetRole changes a database user's role (ends their sessions).
func (s *Service) UserSetRole(a Actor, name, role string) error {
	if err := s.requireAdmin(a); err != nil {
		return err
	}
	if !validRole(role) {
		return invalid("role must be %q or %q", RoleAdmin, RoleUser)
	}
	userMu.Lock()
	defer userMu.Unlock()
	u, err := s.dbUser(name)
	if err != nil {
		return err
	}
	if u.Role == role {
		return nil
	}
	if role != RoleAdmin {
		if err := s.guardAdminLoss(a, u, "demoting"); err != nil {
			return err
		}
	}
	if err := s.store.UserSetRole(u.Name, role); err != nil {
		return err
	}
	s.Audit(a, "user-role name=%s role=%s", u.Name, role)
	return nil
}

// UserSetDisabled disables or re-enables a database user. Disabling ends
// their sessions at once (Lookup refuses a disabled user).
func (s *Service) UserSetDisabled(a Actor, name string, disabled bool) error {
	if err := s.requireAdmin(a); err != nil {
		return err
	}
	userMu.Lock()
	defer userMu.Unlock()
	u, err := s.dbUser(name)
	if err != nil {
		return err
	}
	if u.Disabled == disabled {
		return nil
	}
	if disabled {
		if err := s.guardAdminLoss(a, u, "disabling"); err != nil {
			return err
		}
	}
	if err := s.store.UserSetDisabled(u.Name, disabled); err != nil {
		return err
	}
	verb := "user-enable"
	if disabled {
		verb = "user-disable"
	}
	s.Audit(a, "%s name=%s", verb, u.Name)
	return nil
}

// UserSetPassword sets a database user's password (admin reset; ends their
// sessions). The password is never logged.
func (s *Service) UserSetPassword(a Actor, name, pass string) error {
	if err := s.requireAdmin(a); err != nil {
		return err
	}
	return s.setPassword(a, name, pass, "user-passwd")
}

func (s *Service) setPassword(a Actor, name, pass, verb string) error {
	if err := auth.CheckPolicy(pass); err != nil {
		return invalid("%v", err)
	}
	hash, err := auth.Hash(pass)
	if err != nil {
		return err
	}
	userMu.Lock()
	defer userMu.Unlock()
	u, err := s.dbUser(name)
	if err != nil {
		return err
	}
	if err := s.store.UserSetPassword(u.Name, hash); err != nil {
		return err
	}
	s.Audit(a, "%s name=%s", verb, u.Name)
	return nil
}

// UserDel removes a database user.
func (s *Service) UserDel(a Actor, name string) error {
	if err := s.requireAdmin(a); err != nil {
		return err
	}
	userMu.Lock()
	defer userMu.Unlock()
	u, err := s.dbUser(name)
	if err != nil {
		return err
	}
	if a.User == u.Name {
		return invalid("you can't delete your own account")
	}
	if err := s.guardAdminLoss(a, u, "deleting"); err != nil {
		return err
	}
	if err := s.store.UserDel(u.Name); err != nil {
		return err
	}
	s.Audit(a, "user-del name=%s", u.Name)
	return nil
}

// ChangeOwnPassword lets any database user change their own password after
// proving the current one. A goddns.conf user changes theirs in the file.
func (s *Service) ChangeOwnPassword(a Actor, current, next string) error {
	if a.User == "" {
		return ErrForbidden
	}
	if current == "" || next == "" {
		return missing("current and new password are required")
	}
	if _, ok := s.configHash(a.User); ok {
		return invalid("your login is defined in goddns.conf [admin] users — change it there (goddns passwd)")
	}
	u, err := s.store.UserGet(a.User)
	if err != nil || u.Disabled {
		return ErrForbidden
	}
	if auth.Verify(u.PassHash, current) != nil {
		return invalid("current password is wrong")
	}
	return s.setPassword(a, a.User, next, "account-passwd")
}

// HasAdminLogin reports whether at least one admin can log in (startup check).
func (s *Service) HasAdminLogin() (bool, error) {
	n, err := s.enabledAdmins()
	return n > 0, err
}
