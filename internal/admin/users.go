package admin

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/chrismfz/goddns/internal/service"
)

// handleUsers is the admin's login management page. GET lists every login
// (goddns.conf admins read-only, database users editable) with an add form;
// POST op=add|role|disable|enable|passwd|del changes one (CSRF-checked; the
// service enforces the role, the last-admin guard and audits). Delete is
// two-phase like every destructive action.
func (h *Handler) handleUsers(w http.ResponseWriter, r *http.Request, a service.Actor) {
	if r.Method != http.MethodPost {
		h.renderUsers(w, a, 0, "")
		return
	}
	if !h.csrfOK(a.User, r.FormValue("csrf")) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	var err error
	switch r.FormValue("op") {
	case "add":
		err = h.svc.UserAdd(a, name, r.FormValue("pass"), r.FormValue("role"))
	case "role":
		err = h.svc.UserSetRole(a, name, r.FormValue("role"))
	case "disable":
		err = h.svc.UserSetDisabled(a, name, true)
	case "enable":
		err = h.svc.UserSetDisabled(a, name, false)
	case "passwd":
		err = h.svc.UserSetPassword(a, name, r.FormValue("pass"))
		if err == nil && name == a.User {
			h.setSession(w, a.User) // own reset rotated the fingerprint: stay signed in
		}
	case "grant":
		err = h.svc.Grant(a, name, r.FormValue("zone"))
	case "revoke":
		err = h.svc.Revoke(a, name, r.FormValue("zone"))
	case "del":
		if r.FormValue("confirm") != "1" {
			render(w, userDelTmpl, map[string]any{"Version": h.version, "CSRF": h.csrfFor(a.User), "Name": name})
			return
		}
		err = h.svc.UserDel(a, name)
	default:
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err != nil {
		if service.IsForbidden(err) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		h.renderUsers(w, a, http.StatusBadRequest, err.Error())
		return
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func (h *Handler) renderUsers(w http.ResponseWriter, a service.Actor, code int, msg string) {
	users, err := h.svc.Users(a)
	if err != nil {
		h.renderOpErr(w, err)
		return
	}
	renderStatus(w, code, usersTmpl, map[string]any{
		"Version": h.version, "User": a.User, "Active": "users", "CSRF": h.csrfFor(a.User),
		"Users": users, "Error": msg,
	})
}

// handleAccount lets any login change its own password (database users; a
// goddns.conf admin is told to change it in the file). The session is
// re-issued afterwards, because the password change rotates the credential
// fingerprint the old cookie was bound to.
func (h *Handler) handleAccount(w http.ResponseWriter, r *http.Request, a service.Actor) {
	p, _, _ := h.svc.Lookup(a.User)
	data := map[string]any{
		"Version": h.version, "User": a.User, "Active": "account", "CSRF": h.csrfFor(a.User),
		"Role": a.Role, "Config": p.Config, "Restricted": a.Role != service.RoleAdmin,
	}
	if r.Method != http.MethodPost {
		render(w, accountTmpl, data)
		return
	}
	if !h.csrfOK(a.User, r.FormValue("csrf")) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// The current-password check is a password oracle like /login, so it is
	// throttled like one: per account (a stolen session must not get unlimited
	// guesses) and per source IP.
	keys := []string{"acct:" + a.User, "ip:" + a.Peer}
	for _, k := range keys {
		if until := h.throttle.blockedUntil(k); !until.IsZero() {
			w.Header().Set("Retry-After", strconv.Itoa(int(time.Until(until).Seconds())+1))
			data["Error"] = "too many attempts — wait a minute"
			renderStatus(w, http.StatusTooManyRequests, accountTmpl, data)
			return
		}
	}
	next := r.FormValue("new")
	if next != r.FormValue("repeat") {
		data["Error"] = "the new passwords don't match"
		renderStatus(w, http.StatusBadRequest, accountTmpl, data)
		return
	}
	err := h.svc.ChangeOwnPassword(a, r.FormValue("current"), next)
	switch {
	case errors.Is(err, service.ErrBusy):
		w.Header().Set("Retry-After", "5")
		data["Error"] = "busy — try again in a few seconds"
		renderStatus(w, http.StatusServiceUnavailable, accountTmpl, data)
		return
	case errors.Is(err, service.ErrWrongPassword):
		for _, k := range keys {
			h.throttle.fail(k)
		}
		h.audit(a.User, a.Peer, "account-passwd-failed")
		fallthrough
	case err != nil:
		data["Error"] = err.Error()
		renderStatus(w, http.StatusBadRequest, accountTmpl, data)
		return
	}
	h.throttle.ok("acct:" + a.User)
	h.setSession(w, a.User)
	data["Done"] = true
	data["CSRF"] = h.csrfFor(a.User)
	render(w, accountTmpl, data)
}

// handleUserHome is a non-admin login's landing page: its granted zones and
// the DDNS records in them, with the add form limited to those zones.
func (h *Handler) handleUserHome(w http.ResponseWriter, r *http.Request, a service.Actor) {
	zones, err := h.svc.MyZones(a)
	if err != nil {
		h.renderOpErr(w, err)
		return
	}
	recs, err := h.svc.DDNSList(a)
	if err != nil {
		h.renderOpErr(w, err)
		return
	}
	render(w, userHomeTmpl, map[string]any{
		"Version": h.version, "User": a.User, "Active": "home", "Restricted": true, "Role": a.Role,
		"Zones": zones, "Records": recordViews(recs), "CSRF": h.csrfFor(a.User),
	})
}

const userPages = `
{{define "users"}}{{template "head" .}}{{template "topbar" .}}
<div class="subnav"><span class="here">users</span><span class="sp"></span><span class="muted">goddns {{.Version}}</span></div>
<main>
{{if .Error}}<div class="card" style="border-color:#5a2230;color:#ff8aa6">{{.Error}}</div>{{end}}
<div class="card"><table>
<tr><th>user</th><th>role</th><th>state</th><th>source</th><th>created</th><th>zones</th><th></th></tr>
{{range .Users}}<tr>
<td><b>{{.Name}}</b></td><td>{{.Role}}</td>
<td>{{if .Disabled}}<span class="warn">disabled</span>{{else}}enabled{{end}}</td>
<td>{{if .Config}}<span class="muted" title="[admin] users in goddns.conf">goddns.conf</span>{{else if .Shadowed}}<span class="warn" title="a goddns.conf user of the same name wins">db (shadowed)</span>{{else}}db{{end}}</td>
<td class="muted">{{.Created}}</td>
<td>{{$u := .Name}}{{range .Zones}}<form method="post" action="/users" style="display:inline"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="name" value="{{$u}}"><input type="hidden" name="op" value="revoke"><input type="hidden" name="zone" value="{{.}}"><span>{{.}}</span><button type="submit" title="revoke">×</button></form> {{end}}{{if and (not .Config) (not .Shadowed)}}<form method="post" action="/users" style="display:inline"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="name" value="{{.Name}}"><input type="hidden" name="op" value="grant"><input name="zone" placeholder="zone" size="14"><button type="submit">grant</button></form>{{end}}{{if and .Zones (eq .Role "admin")}} <span class="muted" title="an admin reaches every zone">(unused while admin)</span>{{end}}</td>
<td>{{if .Shadowed}}<form method="post" action="/users" style="display:inline"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="name" value="{{.Name}}"><input type="hidden" name="op" value="del"><button class="danger" type="submit" title="this row can't log in; delete it so it can't come back if the goddns.conf line is removed">delete</button></form>
{{else if not .Config}}
<form method="post" action="/users" style="display:inline"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="name" value="{{.Name}}"><input type="hidden" name="op" value="role">
<select name="role"><option value="admin" {{if eq .Role "admin"}}selected{{end}}>admin</option><option value="user" {{if eq .Role "user"}}selected{{end}}>user</option></select><button type="submit">set role</button></form>
<form method="post" action="/users" style="display:inline"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="name" value="{{.Name}}">
{{if .Disabled}}<input type="hidden" name="op" value="enable"><button type="submit">enable</button>{{else}}<input type="hidden" name="op" value="disable"><button type="submit">disable</button>{{end}}</form>
<form method="post" action="/users" style="display:inline"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="name" value="{{.Name}}"><input type="hidden" name="op" value="passwd">
<input name="pass" type="password" placeholder="new password" autocomplete="new-password"><button type="submit">reset</button></form>
<form method="post" action="/users" style="display:inline"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="name" value="{{.Name}}"><input type="hidden" name="op" value="del"><button class="danger" type="submit">delete</button></form>
{{end}}</td></tr>{{end}}
</table></div>
<div class="card"><form method="post" action="/users">
<input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="op" value="add">
<label>user</label> <input name="name" autocomplete="off">
<label>password</label> <input name="pass" type="password" autocomplete="new-password">
<label>role</label> <select name="role"><option value="user">user</option><option value="admin">admin</option></select>
<button type="submit">add user</button>
</form>
<div class="muted" style="font-size:.72rem;margin-top:.6rem">An <b>admin</b> can do everything. A <b>user</b> manages only the zones granted to it — view, history, record edits, restore, and the DDNS tokens in those zones — plus their own password; nothing server-wide. A grant is one zone, not its subzones. Changing a role, password or state ends that user's sessions. goddns.conf <code>[admin] users</code> are always admins and are edited in the file.</div>
</div>
</main></body></html>{{end}}

{{define "userdel"}}{{template "head" .}}
<header><div><span class="b">goddns admin</span></div><div><a href="/users">cancel</a></div></header>
<main><h2>{{.Name}}</h2>
<div class="card"><p>Delete this user? Their sessions end at once.</p>
<form method="post" action="/users">
<input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="name" value="{{.Name}}">
<input type="hidden" name="op" value="del"><input type="hidden" name="confirm" value="1">
<button class="danger" type="submit">yes, delete</button>
<a href="/users" style="margin-left:1rem;color:#9aa4b2">cancel</a>
</form></div></main></body></html>{{end}}

{{define "account"}}{{template "head" .}}{{template "topbar" .}}
<div class="subnav"><span class="here">account</span><span class="sp"></span><span class="muted">{{.User}} · {{.Role}}</span></div>
<main><h2>change your password</h2>
{{if .Error}}<div class="card" style="border-color:#5a2230;color:#ff8aa6">{{.Error}}</div>{{end}}
{{if .Done}}<div class="card">Password changed. Your other sessions have been signed out.</div>{{end}}
{{if .Config}}<div class="card">Your login is defined in goddns.conf <code>[admin] users</code>. Change it there (<code>goddns passwd -user {{.User}}</code>); the file hot-reloads.</div>
{{else}}<div class="card"><form method="post" action="/account">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<div><label>current password</label><input name="current" type="password" autocomplete="current-password" style="width:100%"></div>
<div style="margin-top:.6rem"><label>new password</label><input name="new" type="password" autocomplete="new-password" style="width:100%"></div>
<div style="margin-top:.6rem"><label>repeat</label><input name="repeat" type="password" autocomplete="new-password" style="width:100%"></div>
<div style="margin-top:.8rem"><button type="submit">change password</button></div>
</form></div>{{end}}
</main></body></html>{{end}}

{{define "userhome"}}{{template "head" .}}{{template "topbar" .}}
<div class="subnav"><span class="here">home</span><span class="sp"></span><span class="muted">{{.User}} · {{.Role}} · goddns {{.Version}}</span></div>
<main>
<h2>your zones</h2>
{{if .Zones}}<div class="card">{{range .Zones}}<div><a href="/zone?name={{.}}">{{.}}</a></div>{{end}}</div>
{{else}}<div class="card">No zones are assigned to your account yet, so there is nothing to manage here. Ask an admin to grant you a zone.</div>{{end}}
{{if .Zones}}
<h2>DDNS records</h2>
{{template "ddnstable" .}}
<div class="card"><form method="post" action="/ddns/add">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<label>hostname</label> <input name="fqdn" placeholder="home.{{index .Zones 0}}" autocomplete="off">
<label>zone</label> <select name="zone">{{range .Zones}}<option value="{{.}}">{{.}}</option>{{end}}</select>
<label>ttl</label> <input name="ttl" value="60" size="5">
<button type="submit">add DDNS record</button>
</form>
<div class="muted" style="font-size:.72rem;margin-top:.5rem">A DDNS record is a token that lets a router or script keep one hostname pointed at its current IP. The token is shown once.</div>
</div>{{end}}
</main></body></html>{{end}}
`
