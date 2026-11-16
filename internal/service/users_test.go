package service

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/chrismfz/goddns/internal/config"
)

func confAdmin(t *testing.T, name, pass string) string {
	h, _ := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.MinCost)
	return name + ":" + string(h)
}

func TestLoginAndLookup(t *testing.T) {
	s, _, _, _ := newSvc(t, "")
	s.cfg().Admin.Users = []string{confAdmin(t, "root", "rootpass1")}
	if err := s.UserAdd(who, "alice", "alicepass1", RoleUser); err != nil {
		t.Fatal(err)
	}
	if p, ok, _ := s.Login("root", "rootpass1"); !ok || p.Role != RoleAdmin || !p.Config {
		t.Fatalf("config admin login: %+v %v", p, ok)
	}
	if p, ok, _ := s.Login("alice", "alicepass1"); !ok || p.Role != RoleUser || p.Config {
		t.Fatalf("db user login: %+v %v", p, ok)
	}
	for _, c := range [][2]string{{"alice", "wrongpass1"}, {"nobody", "whatever1"}, {"root", "alicepass1"}} {
		if _, ok, _ := s.Login(c[0], c[1]); ok {
			t.Fatalf("login %v accepted", c)
		}
	}

	// The fingerprint changes on a role change, a password change; a
	// disabled user doesn't resolve at all — each ends existing sessions.
	_, fp1, ok := s.Lookup("alice")
	if !ok {
		t.Fatal("lookup alice")
	}
	s.UserSetRole(who, "alice", RoleAdmin)
	_, fp2, _ := s.Lookup("alice")
	s.UserSetPassword(who, "alice", "newpass123")
	_, fp3, _ := s.Lookup("alice")
	if fp1 == fp2 || fp2 == fp3 {
		t.Fatal("fingerprint did not change on role/password change")
	}
	s.UserSetDisabled(who, "alice", true)
	if _, _, ok := s.Lookup("alice"); ok {
		t.Fatal("disabled user still resolves")
	}
	if _, ok, _ := s.Login("alice", "newpass123"); ok {
		t.Fatal("disabled user logged in")
	}
}

func TestUserRoleIsFailClosed(t *testing.T) {
	s, _, lines, conf := newSvc(t, "")
	s.ConfPath = conf
	u := Actor{User: "alice", Peer: "192.0.2.9", Role: RoleUser}
	none := Actor{User: "x"} // no role at all
	for _, a := range []Actor{u, none} {
		checks := map[string]error{}
		_, checks["Zones"] = s.Zones(a)
		_, checks["Zone"] = s.Zone(a, "example", false)
		_, checks["History"] = s.History(a, "example")
		_, checks["Inventory"] = s.Inventory(a)
		_, checks["NSVerdicts"] = s.NSVerdicts(a, nil)
		_, checks["EditRecord"] = s.EditRecord(a, "example", ActionAdd, "a 60 IN A 1.1.1.1", true)
		_, checks["Restore"] = s.Restore(a, "example", 1, true)
		_, checks["DDNSList"] = s.DDNSList(a)
		_, checks["DDNSGet"] = s.DDNSGet(a, "x")
		_, _, checks["DDNSAdd"] = s.DDNSAdd(a, "h.example", "example", 0)
		_, _, checks["DDNSRotate"] = s.DDNSRotate(a, "h.example")
		checks["DDNSDel"] = s.DDNSDel(a, "h.example")
		_, checks["TrafficMonthly"] = s.TrafficMonthly(a, 1)
		_, checks["TrafficDaily"] = s.TrafficDaily(a, 1)
		_, checks["VhostList"] = s.VhostList(a)
		_, checks["VhostGet"] = s.VhostGet(a, "h")
		_, checks["VhostSet"] = s.VhostSet(a, "h.example", config.ProxyRule{Upstream: "http://x"}, true)
		_, checks["VhostRemove"] = s.VhostRemove(a, "h.example", true)
		_, checks["Users"] = s.Users(a)
		checks["UserAdd"] = s.UserAdd(a, "eve", "evepass123", RoleAdmin)
		checks["UserSetRole"] = s.UserSetRole(a, "alice", RoleAdmin)
		checks["UserSetDisabled"] = s.UserSetDisabled(a, "alice", true)
		checks["UserSetPassword"] = s.UserSetPassword(a, "alice", "x12345678")
		checks["UserDel"] = s.UserDel(a, "alice")
		for name, err := range checks {
			if !IsForbidden(err) {
				t.Errorf("%s as %q: want ErrForbidden, got %v", name, a.Role, err)
			}
		}
		if m := s.VhostManaged(a); len(m) != 0 {
			t.Errorf("VhostManaged leaked to %q", a.Role)
		}
	}
	if len(*lines) != 0 {
		t.Fatalf("a refused call audited: %v", *lines)
	}
}

func TestLastAdminGuard(t *testing.T) {
	s, _, _, _ := newSvc(t, "")
	// No goddns.conf admins: the database holds the only admins.
	if err := s.UserAdd(who, "alice", "alicepass1", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	alice := Actor{User: "alice", Role: RoleAdmin}
	for name, err := range map[string]error{
		"demote self":  s.UserSetRole(alice, "alice", RoleUser),
		"disable self": s.UserSetDisabled(alice, "alice", true),
		"delete self":  s.UserDel(alice, "alice"),
	} {
		if !IsInvalid(err) {
			t.Fatalf("%s: want refusal, got %v", name, err)
		}
	}
	// Someone else (the CLI) can't remove the last admin either.
	cli := Actor{User: "cli", Role: RoleAdmin}
	if err := s.UserDel(cli, "alice"); err == nil || !strings.Contains(err.Error(), "no admin") {
		t.Fatalf("deleting the last admin: %v", err)
	}
	s.UserAdd(cli, "bob", "bobpass123", RoleAdmin)
	if err := s.UserSetRole(cli, "alice", RoleUser); err != nil {
		t.Fatalf("demote with a second admin present: %v", err)
	}
	if err := s.UserDel(cli, "bob"); err == nil {
		t.Fatal("bob is now the last admin")
	}
	if ok, _ := s.HasAdminLogin(); !ok {
		t.Fatal("HasAdminLogin")
	}
}

func TestUserAddValidation(t *testing.T) {
	s, _, lines, _ := newSvc(t, "")
	s.cfg().Admin.Users = []string{confAdmin(t, "root", "rootpass1")}
	cases := map[string]error{
		"bad name":   s.UserAdd(who, "Alice:x", "alicepass1", RoleUser),
		"bad role":   s.UserAdd(who, "alice", "alicepass1", "owner"),
		"short pass": s.UserAdd(who, "alice", "short", RoleUser),
		"conf name":  s.UserAdd(who, "root", "rootpass12", RoleUser),
	}
	for name, err := range cases {
		if !IsInvalid(err) {
			t.Errorf("%s: want InvalidError, got %v", name, err)
		}
	}
	if err := s.UserAdd(who, "", "", ""); !IsMissing(err) {
		t.Errorf("empty: want Missing, got %v", err)
	}
	s.UserAdd(who, "alice", "alicepass1", RoleUser)
	if err := s.UserAdd(who, "alice", "alicepass2", RoleUser); !IsInvalid(err) {
		t.Errorf("duplicate: %v", err)
	}
	if err := s.UserSetRole(who, "root", RoleUser); !IsInvalid(err) {
		t.Errorf("a goddns.conf admin must not be editable here: %v", err)
	}
	if len(*lines) != 1 || !strings.Contains((*lines)[0], "user-add name=alice role=user") {
		t.Fatalf("audit: %v", *lines)
	}
	for _, l := range *lines {
		if strings.Contains(l, "alicepass") {
			t.Fatal("a password reached the audit log")
		}
	}
}

func TestChangeOwnPassword(t *testing.T) {
	s, _, _, _ := newSvc(t, "")
	s.cfg().Admin.Users = []string{confAdmin(t, "root", "rootpass1")}
	s.UserAdd(who, "alice", "alicepass1", RoleUser)
	alice := Actor{User: "alice", Role: RoleUser}
	if err := s.ChangeOwnPassword(alice, "wrongpass1", "newpass123"); !IsInvalid(err) {
		t.Fatalf("wrong current password: %v", err)
	}
	if err := s.ChangeOwnPassword(alice, "alicepass1", "newpass123"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Login("alice", "newpass123"); !ok {
		t.Fatal("new password does not log in")
	}
	if err := s.ChangeOwnPassword(Actor{User: "root", Role: RoleAdmin}, "rootpass1", "newpass123"); !IsInvalid(err) {
		t.Fatalf("a goddns.conf admin changes it in the file: %v", err)
	}
}

func TestShadowedRowAndGuardWording(t *testing.T) {
	s, _, _, _ := newSvc(t, "")
	s.UserAdd(who, "chris", "chrispass1", RoleAdmin)
	s.UserAdd(who, "solo", "solopass12", RoleAdmin)
	// goddns.conf now defines chris too: the db row is shadowed.
	s.cfg().Admin.Users = []string{confAdmin(t, "chris", "rootpass1")}
	if err := s.UserSetRole(who, "chris", RoleUser); !IsInvalid(err) {
		t.Fatalf("a shadowed row stays read-only except delete: %v", err)
	}
	if err := s.UserDel(who, "chris"); err != nil {
		t.Fatalf("deleting a shadowed row must work: %v", err)
	}
	if _, err := s.store.UserGet("chris"); err == nil {
		t.Fatal("shadowed row not deleted")
	}
	// the goddns.conf chris still logs in
	if _, ok, _ := s.Login("chris", "rootpass1"); !ok {
		t.Fatal("goddns.conf chris lost")
	}
	solo := Actor{User: "solo", Role: RoleAdmin}
	for verb, err := range map[string]error{
		"demote":  s.UserSetRole(solo, "solo", RoleUser),
		"disable": s.UserSetDisabled(solo, "solo", true),
		"delete":  s.UserDel(solo, "solo"),
	} {
		if err == nil || err.Error() != "you can't "+verb+" your own account" {
			t.Errorf("%s self: %v", verb, err)
		}
	}
}

func TestAuditSanitizesNames(t *testing.T) {
	s, _, lines, _ := newSvc(t, "")
	s.Audit(Actor{User: "x peer=1.2.3.4 login-ok\nadmin-audit user=chris", Peer: "?"}, "login-failed")
	s.Audit(Actor{User: "", Peer: "192.0.2.1"}, "login-failed")
	if strings.ContainsAny((*lines)[0], "\n") || strings.Count((*lines)[0], "=") != 2 || strings.Count((*lines)[0], " ") != 3 {
		t.Fatalf("crafted name forged audit fields: %q", (*lines)[0])
	}
	if (*lines)[1] != `admin-audit user="" peer=192.0.2.1 login-failed` {
		t.Fatalf("empty user: %q", (*lines)[1])
	}
}
