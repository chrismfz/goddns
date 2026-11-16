package service

import (
	"errors"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/chrismfz/goddns/internal/store"
)

// API token scopes. A token acts as its user — never with more than that
// login's role and zone grants — and its scopes narrow it further: each
// endpoint needs one scope, and the service still applies the role/grant
// check behind it.
const (
	ScopeZonesRead    = "zones:read"    // zone list, records, history
	ScopeRecordsWrite = "records:write" // record add/del, restore
	ScopeDDNSRead     = "ddns:read"     // list DDNS records
	ScopeDDNSWrite    = "ddns:write"    // add / rotate / delete DDNS records
	ScopeProxyRead    = "proxy:read"    // list proxy vhosts (admin)
	ScopeProxyWrite   = "proxy:write"   // set / remove proxy vhosts (admin)
	ScopeUsersAdmin   = "users:admin"   // list users, grant / revoke zones (admin)
)

// scopesFor is what a role may put on a token: a user-role token can't carry
// a scope its owner could never use.
var scopesFor = map[string][]string{
	RoleUser:  {ScopeZonesRead, ScopeRecordsWrite, ScopeDDNSRead, ScopeDDNSWrite},
	RoleAdmin: {ScopeZonesRead, ScopeRecordsWrite, ScopeDDNSRead, ScopeDDNSWrite, ScopeProxyRead, ScopeProxyWrite, ScopeUsersAdmin},
}

// AllScopes lists every scope (for help texts and forms).
func AllScopes() []string { return append([]string(nil), scopesFor[RoleAdmin]...) }

// ScopesFor lists the scopes a login with role may hold.
func ScopesFor(role string) []string { return append([]string(nil), scopesFor[role]...) }

// ErrUnauthorized is any failed API authentication: unknown, expired, from a
// disallowed address, or owned by a login that can't sign in any more. One
// error for all, so a caller learns nothing about which.
var ErrUnauthorized = errors.New("unauthorized")

var tokenNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// APITokenInfo is a token as listed (never the hash).
type APITokenInfo struct {
	ID        int64
	Name      string
	User      string
	Scopes    []string
	AllowNets []string
	Expires   string // "never" or a date
	Created   string
	LastUsed  string // "never" or a time
	Expired   bool
}

func tokenInfo(t store.APIToken) APITokenInfo {
	i := APITokenInfo{ID: t.ID, Name: t.Name, User: t.User, Scopes: t.Scopes, AllowNets: t.AllowNets,
		Expires: "never", Created: t.CreatedAt.Format("2006-01-02"), LastUsed: "never"}
	if !t.ExpiresAt.IsZero() {
		i.Expires = t.ExpiresAt.Format("2006-01-02")
		i.Expired = time.Now().After(t.ExpiresAt)
	}
	if !t.LastUsed.IsZero() {
		i.LastUsed = t.LastUsed.Format("2006-01-02 15:04")
	}
	return i
}

// canManageTokensOf: an admin manages anyone's tokens, a user only its own.
func canManageTokensOf(a Actor, owner string) error {
	if a.Role == RoleAdmin || (a.Role == RoleUser && a.User == owner) {
		return nil
	}
	return ErrForbidden
}

// APITokenCreate mints a token for owner (yourself, or anyone as an admin)
// and returns its plaintext — shown once. expiresDays 0 = never expires.
func (s *Service) APITokenCreate(a Actor, owner, name string, scopes, allowNets []string, expiresDays int) (APITokenInfo, string, error) {
	owner, name = strings.TrimSpace(owner), strings.ToLower(strings.TrimSpace(name))
	if owner == "" {
		owner = a.User
	}
	if err := canManageTokensOf(a, owner); err != nil {
		return APITokenInfo{}, "", err
	}
	if a.Via != "" {
		// an API token can't mint more API tokens: a leaked one must not be
		// able to make itself permanent
		return APITokenInfo{}, "", ErrForbidden
	}
	if name == "" || len(scopes) == 0 {
		return APITokenInfo{}, "", missing("a name and at least one scope are required")
	}
	if !tokenNameRe.MatchString(name) {
		return APITokenInfo{}, "", invalid("token name %q: use 1-64 of a-z 0-9 . _ -", name)
	}
	p, _, ok := s.Lookup(owner)
	if !ok {
		return APITokenInfo{}, "", invalid("no enabled login %q", owner)
	}
	allowed := map[string]bool{}
	for _, sc := range scopesFor[p.Role] {
		allowed[sc] = true
	}
	seen := map[string]bool{}
	var clean []string
	for _, sc := range scopes {
		sc = strings.TrimSpace(sc)
		if sc == "" || seen[sc] {
			continue
		}
		if !allowed[sc] {
			return APITokenInfo{}, "", invalid("scope %q is not available to %s (role %s)", sc, owner, p.Role)
		}
		seen[sc] = true
		clean = append(clean, sc)
	}
	if len(clean) == 0 {
		return APITokenInfo{}, "", missing("at least one scope is required")
	}
	var nets []string
	for _, n := range allowNets {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if !strings.Contains(n, "/") { // a bare address is a single-host net
			if ip := net.ParseIP(n); ip != nil && ip.To4() != nil {
				n += "/32"
			} else {
				n += "/128"
			}
		}
		_, ipn, err := net.ParseCIDR(n)
		if err != nil {
			return APITokenInfo{}, "", invalid("allow %q: %v", n, err)
		}
		nets = append(nets, ipn.String())
	}
	if expiresDays < 0 {
		return APITokenInfo{}, "", invalid("expiry must be 0 (never) or a number of days")
	}
	var exp time.Time
	if expiresDays > 0 {
		exp = time.Now().Add(time.Duration(expiresDays) * 24 * time.Hour)
	}
	t, plain, err := s.store.APITokenAdd(p.Name, name, clean, nets, exp)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			return APITokenInfo{}, "", invalid("%v", err)
		}
		return APITokenInfo{}, "", err
	}
	s.Audit(a, "apitoken-add owner=%s name=%s scopes=%s allow=%s expires=%s",
		p.Name, name, strings.Join(clean, ","), strings.Join(nets, ","), tokenInfo(t).Expires)
	return tokenInfo(t), plain, nil
}

// APITokens lists owner's tokens; an admin may pass "" for everyone's.
func (s *Service) APITokens(a Actor, owner string) ([]APITokenInfo, error) {
	if owner == "" && a.Role != RoleAdmin {
		owner = a.User
	}
	if owner != "" {
		if err := canManageTokensOf(a, owner); err != nil {
			return nil, err
		}
	}
	ts, err := s.store.APITokenList(owner)
	if err != nil {
		return nil, err
	}
	out := make([]APITokenInfo, 0, len(ts))
	for _, t := range ts {
		out = append(out, tokenInfo(t))
	}
	return out, nil
}

// APITokenRevoke deletes a token (yours, or anyone's as an admin).
func (s *Service) APITokenRevoke(a Actor, id int64) error {
	t, err := s.store.APITokenGet(id)
	if err != nil {
		if errors.Is(err, store.ErrNoAPIToken) {
			if a.Role == RoleAdmin {
				return invalid("no API token #%d", id)
			}
			return ErrForbidden // don't tell a user which ids exist
		}
		return err
	}
	if err := canManageTokensOf(a, t.User); err != nil {
		return err
	}
	if err := s.store.APITokenDel(id); err != nil {
		return err
	}
	s.Audit(a, "apitoken-del owner=%s name=%s", t.User, t.Name)
	return nil
}

// AuthenticateAPI turns a bearer token into the Actor it acts as, plus its
// scopes. The token's owner is resolved NOW (Lookup): a disabled, deleted or
// demoted login takes its tokens down with it at once, and a role change
// applies on the next request.
func (s *Service) AuthenticateAPI(tok string, peer net.IP) (Actor, []string, error) {
	if !strings.HasPrefix(tok, store.APITokenPrefix) {
		return Actor{}, nil, ErrUnauthorized
	}
	t, err := s.store.APITokenLookup(tok)
	if err != nil {
		return Actor{}, nil, ErrUnauthorized
	}
	now := time.Now()
	if !t.ExpiresAt.IsZero() && now.After(t.ExpiresAt) {
		return Actor{}, nil, ErrUnauthorized
	}
	if len(t.AllowNets) > 0 {
		in := false
		for _, n := range t.AllowNets {
			if _, ipn, err := net.ParseCIDR(n); err == nil && peer != nil && ipn.Contains(peer) {
				in = true
				break
			}
		}
		if !in {
			return Actor{}, nil, ErrUnauthorized
		}
	}
	p, _, ok := s.Lookup(t.User)
	if !ok {
		return Actor{}, nil, ErrUnauthorized
	}
	_ = s.store.APITokenTouch(t.ID, now) // best-effort "last used"
	peerStr := "?"
	if peer != nil {
		peerStr = peer.String()
	}
	return Actor{User: p.Name, Peer: peerStr, Role: p.Role, Via: "api:" + t.Name}, t.Scopes, nil
}

// HasScope reports whether scopes contains want.
func HasScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}
