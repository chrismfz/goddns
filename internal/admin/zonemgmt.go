package admin

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/chrismfz/goddns/internal/service"
)

// assignable lists the user-role logins a new zone can be assigned to.
func (h *Handler) assignable(a service.Actor) []string {
	if a.Role != service.RoleAdmin {
		return nil
	}
	us, err := h.svc.Users(a)
	if err != nil {
		return nil
	}
	var out []string
	for _, u := range us {
		if u.Role == service.RoleUser && !u.Config && !u.Shadowed && !u.Disabled {
			out = append(out, u.Name)
		}
	}
	return out
}

func splitNS(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(c rune) bool { return c == ',' || c == ' ' || c == '\n' || c == '\r' || c == '\t' }) {
		out = append(out, f)
	}
	return out
}

// handleZoneCreate creates a managed zone (admin). Two-phase: the first POST
// shows the file, the include stanza and what the zone would shadow in its
// parent; confirm=1 creates it (and assigns it, if asked).
func (h *Handler) handleZoneCreate(w http.ResponseWriter, r *http.Request, a service.Actor) {
	if r.Method != http.MethodPost || !h.csrfOK(a.User, r.FormValue("csrf")) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	zone, ns, assign := r.FormValue("zone"), splitNS(r.FormValue("ns")), r.FormValue("assign")
	apply := r.FormValue("confirm") == "1"
	p, err := h.svc.ZoneCreate(a, zone, ns, assign, apply)
	if err != nil {
		h.renderOpErr(w, err)
		return
	}
	if !apply {
		render(w, zoneConfirmTmpl, map[string]any{
			"Version": h.version, "CSRF": h.csrfFor(a.User), "Create": true, "P": p,
			"Zone": zone, "NS": strings.Join(ns, ", "), "Assign": assign,
		})
		return
	}
	http.Redirect(w, r, "/zone?name="+url.QueryEscape(p.Zone), http.StatusSeeOther)
}

// handleZoneDelete deletes a managed zone (admin), two-phase like create.
func (h *Handler) handleZoneDelete(w http.ResponseWriter, r *http.Request, a service.Actor) {
	if r.Method != http.MethodPost || !h.csrfOK(a.User, r.FormValue("csrf")) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	zone := r.FormValue("zone")
	apply := r.FormValue("confirm") == "1"
	p, err := h.svc.ZoneDelete(a, zone, apply)
	if err != nil {
		h.renderOpErr(w, err)
		return
	}
	if !apply {
		render(w, zoneConfirmTmpl, map[string]any{"Version": h.version, "CSRF": h.csrfFor(a.User), "P": p, "Zone": zone})
		return
	}
	http.Redirect(w, r, "/zones", http.StatusSeeOther)
}

const zonePages = `
{{define "zoneconfirm"}}{{template "head" .}}
<header><div><span class="b">goddns admin</span></div><div><a href="/zones">cancel</a></div></header>
<main><h2>{{if .Create}}create{{else}}delete{{end}} zone {{.P.Zone}}</h2>
<div class="card">
{{if .Create}}
<div>zone file <code>{{.P.File}}</code>:</div>
<pre style="margin:.4rem 0">{{.P.Content}}</pre>
<div>added to the managed include:</div><pre style="margin:.4rem 0">{{.P.Stanza}}</pre>
{{if .Assign}}<div>assigned to <b>{{.Assign}}</b> once created.</div>{{end}}
{{if .P.Parent}}<div class="warn" style="margin-top:.6rem">This zone is inside <b>{{.P.Parent}}</b>, served here too. BIND answers from the most specific zone, so these records of {{.P.Parent}} stop being answered:</div>
{{if .P.Shadowed}}<pre style="margin:.4rem 0">{{range .P.Shadowed}}{{.}}
{{end}}</pre>{{else}}<div class="muted">(none found)</div>{{end}}
{{if not .P.Delegated}}<div class="warn">{{.P.Parent}} has no NS records for {{.P.Zone}}: resolvers on the internet won't find it until you add the delegation there.</div>{{end}}{{end}}
{{else}}
<div>removed from the managed include:</div><pre style="margin:.4rem 0">{{.P.Stanza}}</pre>
<div>its file <code>{{.P.File}}</code> is moved aside to <code>….deleted-&lt;time&gt;</code>, not deleted; every grant on the zone is removed.</div>
{{end}}
<form method="post" action="{{if .Create}}/zones/create{{else}}/zones/delete{{end}}" style="margin-top:.8rem">
<input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="zone" value="{{.Zone}}">
{{if .Create}}<input type="hidden" name="ns" value="{{.NS}}"><input type="hidden" name="assign" value="{{.Assign}}">{{end}}
<input type="hidden" name="confirm" value="1">
<button {{if not .Create}}class="danger"{{end}} type="submit">{{if .Create}}yes, create it{{else}}yes, delete it{{end}}</button>
<a href="/zones" style="margin-left:1rem;color:#9aa4b2">cancel</a>
</form></div></main></body></html>{{end}}
`
