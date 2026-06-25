package admin

import (
	"html/template"
	"log"
	"net/http"
)

const (
	loginTmpl          = "login"
	dashTmpl           = "dash"
	resultTmpl         = "result"
	logsTmpl           = "logs"
	confirmTmpl        = "confirm"
	helpTmpl           = "help"
	zonesTmpl          = "zones"
	zoneViewTmpl       = "zoneview"
	zoneHistTmpl       = "zonehist"
	recordConfirmTmpl  = "recordconfirm"
	restoreConfirmTmpl = "restoreconfirm"
	proxyFormTmpl      = "proxyform"
	proxyConfirmTmpl   = "proxyconfirm"
	passwdTmpl         = "passwd"
)

var tmpls = template.Must(template.New("").Parse(pages))

func render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	// Locked-down CSP: no scripts at all, inline styles only, forms only to
	// self. Defence in depth behind html/template auto-escaping.
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	if err := tmpls.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("admin: template %s: %v", name, err)
	}
}

const pages = `
{{define "head"}}<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>goddns admin</title><style>
:root{color-scheme:dark}
body{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:#0f1115;color:#d7dae0;margin:0;padding:0}
header{background:#161a21;border-bottom:1px solid #262c36;padding:.7rem 1rem;display:flex;justify-content:space-between;align-items:center}
header .b{color:#18bcf2;font-weight:bold}
header a{color:#9aa4b2;text-decoration:none;margin-left:1rem}
header nav a.on{color:#18bcf2}
.subnav{background:#11151c;border-bottom:1px solid #1d222b;padding:.45rem 1rem;display:flex;gap:1rem;align-items:center;font-size:.82rem}
.subnav a{color:#9aa4b2;text-decoration:none}
.subnav .here{color:#8ab4f8;font-weight:bold}
.subnav .sp{flex:1}
main{max-width:1100px;margin:0 auto;padding:1rem}
h2{color:#8ab4f8;font-size:1rem;margin:1.4rem 0 .5rem;border-bottom:1px solid #262c36;padding-bottom:.3rem}
table{width:100%;border-collapse:collapse;font-size:.86rem}
th,td{text-align:left;padding:.35rem .5rem;border-bottom:1px solid #1d222b}
th{color:#7d8696;font-weight:normal}
tr:hover td{background:#141821}
input,select{background:#0c0e12;color:#d7dae0;border:1px solid #2a313c;border-radius:4px;padding:.35rem .5rem;font:inherit}
button{background:#18bcf2;color:#06222c;border:0;border-radius:4px;padding:.4rem .8rem;font:inherit;font-weight:bold;cursor:pointer}
button.danger{background:#3a2230;color:#ff8aa6}
.muted{color:#6b7280}.ok{color:#52d273}.warn{color:#e7b84b}.err{color:#ff8aa6}
.card{background:#13171e;border:1px solid #232a34;border-radius:8px;padding:1rem;margin:1rem 0}
.tok{background:#06222c;border:1px solid #18bcf2;border-radius:6px;padding:.6rem;word-break:break-all;color:#bfeefc}
form.inline{display:inline}
.row{display:flex;gap:.5rem;flex-wrap:wrap;align-items:end}
label{display:block;font-size:.75rem;color:#7d8696;margin-bottom:.2rem}
pre{background:#0a0c10;border:1px solid #1d222b;border-radius:6px;padding:.6rem;overflow:auto;max-height:60vh;font-size:.78rem;line-height:1.35}
</style></head><body>{{end}}

{{/* topbar: the persistent main nav, identical on every signed-in page so the
   menu never disappears. .Active selects which link is highlighted. */}}
{{define "topbar"}}<header>
<div><a href="/" class="b">goddns admin</a><nav>
<a href="/" {{if eq .Active "dash"}}class="on"{{end}}>dashboard</a>
<a href="/zones" {{if eq .Active "zones"}}class="on"{{end}}>zones</a>
<a href="/logs?which=access" {{if eq .Active "logs"}}class="on"{{end}}>logs</a>
<a href="/passwd" {{if eq .Active "passwd"}}class="on"{{end}}>password</a>
</nav></div>
<div><span class="muted">{{.User}}</span><a href="/logout">logout</a></div>
</header>{{end}}

{{define "login"}}{{template "head" .}}
<main style="max-width:340px;margin-top:12vh">
<div class="b" style="color:#18bcf2;font-size:1.3rem;margin-bottom:1rem">goddns admin</div>
{{if .Error}}<div class="card" style="border-color:#5a2230;color:#ff8aa6">{{.Error}}</div>{{end}}
<form method="post" action="/login" class="card">
<div><label>user</label><input name="user" autofocus autocomplete="username" style="width:100%"></div>
<div style="margin-top:.6rem"><label>password</label><input name="pass" type="password" autocomplete="current-password" style="width:100%"></div>
<div style="margin-top:.9rem"><button type="submit">sign in</button></div>
</form>
<div class="muted" style="font-size:.7rem;margin-top:1rem">goddns {{.Version}}</div>
</main></body></html>{{end}}

{{define "dash"}}{{template "head" .}}{{template "topbar" .}}
<div class="subnav"><span class="here">dashboard</span><span class="sp"></span><span class="muted">goddns {{.Version}}</span></div>
<main>

<h2>DDNS records</h2>
<table><thead><tr><th>FQDN</th><th>zone</th><th>TTL</th><th>last IP</th><th>last change</th><th>last seen</th><th>state</th><th></th></tr></thead><tbody>
{{range .Records}}<tr>
<td>{{.FQDN}}</td><td class="muted">{{.Zone}}</td><td>{{.TTL}}</td>
<td>{{if .LastIP}}{{.LastIP}}{{else}}<span class="muted">—</span>{{end}}</td>
<td class="muted">{{.LastChange}}</td>
<td class="muted">{{.LastSeen}}</td>
<td>{{if eq .State "enabled"}}<span class="ok">{{.State}}</span>{{else}}<span class="warn">{{.State}}</span>{{end}}</td>
<td style="white-space:nowrap">
<a href="/ddns/help?fqdn={{.FQDN}}">help</a>
<form class="inline" method="post" action="/ddns/rotate"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="fqdn" value="{{.FQDN}}"><button type="submit">rotate</button></form>
<form class="inline" method="post" action="/ddns/del"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="fqdn" value="{{.FQDN}}"><button class="danger" type="submit">delete</button></form>
</td>
</tr>{{else}}<tr><td colspan="8" class="muted">(no records)</td></tr>{{end}}
</tbody></table>

<div class="card"><form method="post" action="/ddns/add"><div class="row">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<div><label>fqdn</label><input name="fqdn" placeholder="home.ddns.myip.gr" size="26"></div>
<div><label>zone</label><input name="zone" placeholder="ddns.myip.gr" size="20"></div>
<div><label>ttl</label><input name="ttl" type="number" value="60" size="6" style="width:5rem"></div>
<div><button type="submit">add token</button></div>
</div></form></div>

{{if .ProxyOn}}<h2>proxy hosts</h2>
<table><thead><tr><th>host</th><th>upstream</th><th>allow</th><th>auth</th><th>rate</th>{{if .ProxyEdit}}<th></th>{{end}}</tr></thead><tbody>
{{range .Proxies}}<tr>
<td>{{.Host}}</td><td class="muted">{{.Upstream}}</td>
<td>{{if .Allow}}{{.Allow}}{{else}}<span class="warn">any</span>{{end}}</td>
<td>{{if .Auth}}<span class="ok">basic</span>{{else}}<span class="muted">—</span>{{end}}</td>
<td>{{if .Rate}}{{.Rate}}/s{{else}}<span class="muted">—</span>{{end}}</td>
{{if $.ProxyEdit}}<td style="white-space:nowrap">{{if .Managed}}
<a href="/proxy/edit?host={{.Host}}">edit</a>
<form class="inline" method="post" action="/proxy/del"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="host" value="{{.Host}}"><button class="danger" type="submit">del</button></form>
{{else}}<span class="muted" title="defined in goddns.conf">conf</span>{{end}}</td>{{end}}
</tr>{{else}}<tr><td colspan="{{if .ProxyEdit}}6{{else}}5{{end}}" class="muted">(no proxy hosts)</td></tr>{{end}}
</tbody></table>
{{if .ProxyEdit}}
<div class="card"><form method="post" action="/proxy/set"><input type="hidden" name="csrf" value="{{.CSRF}}"><div class="row">
<div><label>host</label><input name="host" placeholder="idrac.internal.myip.gr" size="26"></div>
<div><label>upstream</label><input name="upstream" placeholder="https://10.23.0.5" size="22"></div>
<div><label>allow (CIDRs)</label><input name="allow" placeholder="10.0.0.0/8" size="16"></div>
<div><label>rate/s</label><input name="rate" type="number" value="0" style="width:5rem"></div>
<div><label>verify</label><input type="checkbox" name="verify" value="1"></div>
<div><label>preserve host</label><input type="checkbox" name="preserve" value="1"></div>
<div><button type="submit">add vhost</button></div>
</div>
<div class="row" style="margin-top:.4rem">
<div><label>login user (optional)</label><input name="auth_user" placeholder="chris" size="14" autocomplete="off"></div>
<div><label>login password</label><input name="auth_pass" type="password" placeholder="bcrypt-hashed for you" size="20" autocomplete="new-password"></div>
<div class="muted" style="font-size:.7rem;align-self:center">→ stored bcrypt-hashed; leave blank for IP-only</div>
</div>
</form></div>
<div class="muted" style="font-size:.72rem;margin-top:.4rem">goddns manages <code>proxy.d/&lt;host&gt;.conf</code> fragments; vhosts marked <span class="muted">conf</span> live in goddns.conf and stay read-only here.</div>
{{else}}<div class="muted" style="font-size:.72rem;margin-top:.4rem">proxy hosts are read-only here — edit goddns.conf (hot-reloaded). DDNS records are managed above.</div>{{end}}

{{if .HasStats}}
<h2>Proxy traffic <span class="muted" style="font-size:.7rem;font-weight:normal">since start · live</span></h2>
<table><thead><tr><th>host</th><th>active</th><th>requests</th><th>in</th><th>out</th><th>2xx / 3xx / 4xx / 5xx</th><th>last seen</th></tr></thead><tbody>
{{range .ProxyStats}}<tr>
<td>{{.Host}}</td>
<td>{{.Active}}</td>
<td>{{.Requests}}</td>
<td>{{.In}}</td>
<td>{{.Out}}</td>
<td class="muted">{{.Codes}}</td>
<td class="muted">{{.LastSeen}}</td>
</tr>{{else}}<tr><td colspan="7" class="muted">(no traffic yet)</td></tr>{{end}}
</tbody></table>
{{end}}
{{end}}

</main></body></html>{{end}}

{{define "proxyform"}}{{template "head" .}}
<header><div><span class="b">goddns admin</span> <span class="muted">{{if .Edit}}edit{{else}}add{{end}} vhost</span></div><div><a href="/">cancel</a></div></header>
<main><h2>{{if .Edit}}edit {{.Host}}{{else}}add a proxy vhost{{end}}</h2>
<div class="card"><form method="post" action="/proxy/set"><input type="hidden" name="csrf" value="{{.CSRF}}">
<div><label>host</label><input name="host" value="{{.Host}}" {{if .Edit}}readonly{{end}} placeholder="idrac.internal.myip.gr" style="width:100%"></div>
<div style="margin-top:.6rem"><label>upstream</label><input name="upstream" value="{{.Upstream}}" placeholder="https://10.23.0.5" style="width:100%"></div>
<div style="margin-top:.6rem"><label>allow (CIDRs, comma/space separated)</label><input name="allow" value="{{.Allow}}" placeholder="10.0.0.0/8" style="width:100%"></div>
<div style="margin-top:.6rem"><label>basic_auth (user:bcrypt, one per line — existing entries; edit/clear to remove)</label><textarea name="auth" rows="2" style="width:100%;background:#0c0e12;color:#d7dae0;border:1px solid #2a313c;border-radius:4px;padding:.35rem .5rem;font:inherit">{{.Auth}}</textarea></div>
<div class="row" style="margin-top:.6rem">
<div><label>+ add login user</label><input name="auth_user" placeholder="chris" autocomplete="off"></div>
<div><label>+ password</label><input name="auth_pass" type="password" placeholder="bcrypt-hashed for you" autocomplete="new-password"></div>
<div class="muted" style="font-size:.7rem;align-self:center">appended to basic_auth on save</div>
</div>
<div class="row" style="margin-top:.6rem">
<div><label>rate/s</label><input name="rate" type="number" value="{{.Rate}}" style="width:5rem"></div>
<div><label>verify upstream TLS</label><input type="checkbox" name="verify" value="1" {{if .Verify}}checked{{end}}></div>
<div><label>preserve host</label><input type="checkbox" name="preserve" value="1" {{if .Preserve}}checked{{end}}></div>
</div>
<div style="margin-top:.8rem"><button type="submit">preview</button><a href="/" style="margin-left:1rem;color:#9aa4b2">cancel</a></div>
</form></div></main></body></html>{{end}}

{{define "proxyconfirm"}}{{template "head" .}}
<header><div><span class="b">goddns admin</span> <span class="muted">confirm</span></div><div><a href="/">cancel</a></div></header>
<main><h2>{{.Action}} vhost {{.Host}}</h2>
<div class="card">
<pre>{{.Fragment}}</pre>
<form method="post" action="/proxy/set">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<input type="hidden" name="host" value="{{.Host}}">
<input type="hidden" name="upstream" value="{{.Upstream}}">
<input type="hidden" name="allow" value="{{.Allow}}">
<input type="hidden" name="auth" value="{{.Auth}}">
<input type="hidden" name="rate" value="{{.Rate}}">
{{if .Verify}}<input type="hidden" name="verify" value="1">{{end}}
{{if .Preserve}}<input type="hidden" name="preserve" value="1">{{end}}
<input type="hidden" name="confirm" value="1">
<button type="submit">{{.Action}}</button>
<a href="/" style="margin-left:1rem;color:#9aa4b2">cancel</a>
</form></div></main></body></html>{{end}}

{{define "result"}}{{template "head" .}}
<header><div><span class="b">goddns admin</span></div><div><a href="/">&larr; back</a></div></header>
<main>
{{if .Error}}<div class="card" style="border-color:#5a2230;color:#ff8aa6">{{.Error}}</div>
{{else}}
<h2>token created</h2>
<div class="card">
<div><b>{{.FQDN}}</b> <span class="muted">zone {{.Zone}}, ttl {{.TTL}}</span></div>
<div style="margin:.7rem 0 .3rem" class="warn">Copy it now — shown once, never stored in clear:</div>
<div class="tok">{{.Token}}</div>
<div class="muted" style="margin-top:.7rem">test: <code>curl "https://&lt;host&gt;:8245/update/{{.Token}}"</code></div>
<div class="warn" style="margin-top:.5rem;font-size:.78rem">The URL is the credential — never paste it into chats (link previews will fetch it).</div>
</div>{{end}}
<a href="/">&larr; back to dashboard</a>
</main></body></html>{{end}}

{{define "confirm"}}{{template "head" .}}
<header><div><span class="b">goddns admin</span></div><div><a href="/">cancel</a></div></header>
<main><h2>{{.FQDN}}</h2>
<div class="card">
<p>{{.Msg}}</p>
<form method="post" action="{{.Action}}">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<input type="hidden" name="fqdn" value="{{.FQDN}}">
{{if .Host}}<input type="hidden" name="host" value="{{.Host}}">{{end}}
<input type="hidden" name="confirm" value="1">
<button class="danger" type="submit">{{.Verb}}</button>
<a href="/" style="margin-left:1rem;color:#9aa4b2">cancel</a>
</form></div></main></body></html>{{end}}

{{define "help"}}{{template "head" .}}
<header><div><span class="b">goddns admin</span> <span class="muted">{{.Name}}</span></div><div><a href="/">&larr; dashboard</a></div></header>
<main>
{{if .NewToken}}<h2>token for {{.Name}}</h2>
<div class="card"><div class="warn" style="margin-bottom:.4rem">Save it now — shown once, only the hash is stored:</div>
<div class="tok">{{.Token}}</div>
<div class="warn" style="margin-top:.5rem;font-size:.78rem">The URL below IS the credential — never paste it into chats (link previews will fetch it and flip your record).</div></div>
{{else}}<h2>client setup for {{.Name}}</h2>
<div class="muted" style="margin-bottom:.6rem">goddns stores only the token's hash, so it can't be shown again. Lost it? Use <b>rotate</b> on the dashboard to mint a new one — then this page fills in below.</div>
{{end}}

<h2>curl (one-shot / cron)</h2>
<pre># server uses the source IP of the connection — the client needn't know its own
curl "https://{{.Host}}:{{.Port}}/update/{{.Token}}"

# explicit IP instead
curl "https://{{.Host}}:{{.Port}}/update/{{.Token}}?ip=203.0.113.10"

# cron, every 3 minutes (nochg responses cost nothing):
*/3 * * * * curl -fsS "https://{{.Host}}:{{.Port}}/update/{{.Token}}" >/dev/null 2>&1</pre>

<h2>MikroTik RouterOS (one import)</h2>
<pre>/system script add name=goddns source="/tool fetch url=\"https://{{.Host}}:{{.Port}}/update/{{.Token}}\" output=none"
/system scheduler add name=goddns interval=3m on-event=goddns comment="goddns DDNS"</pre>

<h2>Router with "Custom DDNS" (DynDNS2)</h2>
<pre>server / hostname : {{.Host}}:{{.Port}}
update URL        : /nic/update?hostname={{.Name}}&myip=&lt;ip&gt;
username          : (anything)
password          : {{.Token}}
# or as a plain URL with the token in the query:
curl "https://{{.Host}}:{{.Port}}/nic/update?hostname={{.Name}}&token={{.Token}}&myip=203.0.113.10"</pre>

<div class="muted" style="font-size:.74rem">Responses: good &lt;ip&gt; (updated), nochg &lt;ip&gt; (no change), badauth (bad token), nohost (hostname mismatch).{{if not .NewToken}} Replace <b>&lt;token&gt;</b> above with the record's token (or rotate to get a fresh one).{{end}}</div>
<p style="margin-top:1rem"><a href="/">&larr; back to dashboard</a></p>
</main></body></html>{{end}}

{{define "zones"}}{{template "head" .}}{{template "topbar" .}}
<div class="subnav"><span class="here">zones</span><span class="muted">read-only</span><span class="sp"></span><a href="/zones">refresh</a></div>
<main>
{{if .Error}}
<div class="card" style="border-color:#5a2230">
<div class="warn">Can't read the BIND config:</div>
<pre style="margin:.5rem 0">{{.Error}}</pre>
<div class="muted" style="font-size:.8rem">goddns runs as the <code>goddns</code> user. To let it read named.conf for this
read-only view, add it to the named group:<br>
&nbsp;&nbsp;<code>usermod -aG named goddns &amp;&amp; systemctl restart goddns</code><br>
(or just use the CLI as root: <code>goddns zones</code>). This page never edits anything.</div>
</div>
{{else}}

<h2>zones{{if .Directory}} <span class="muted">(directory {{.Directory}})</span>{{end}}</h2>
<table><thead><tr>{{if .HasViews}}<th>view</th>{{end}}<th>zone</th><th>kind</th><th>file</th><th>update key(s)</th>{{if .Checked}}<th>NS (live)</th>{{end}}</tr></thead><tbody>
{{range .Zones}}<tr>
{{if $.HasViews}}<td class="muted">{{if .View}}{{.View}}{{else}}_default{{end}}</td>{{end}}
<td><a href="/zone?name={{.Name}}">{{.Name}}</a></td>
<td>{{if .Dynamic}}<span class="ok">{{.Kind}}</span>{{else}}<span class="muted">{{.Kind}}</span>{{end}}</td>
<td>{{if .File}}{{.File}}{{if .Status}} <span class="{{if eq .Status "missing"}}err{{else if eq .Status "no journal yet"}}warn{{else}}muted{{end}}">({{.Status}})</span>{{end}}{{else}}<span class="muted">—</span>{{end}}</td>
<td>{{if .Keys}}{{.Keys}}{{else}}<span class="muted">—</span>{{end}}</td>
{{if $.Checked}}<td>{{if .NS}}<span class="{{.NSClass}}">{{.NS}}</span>{{else}}<span class="muted">—</span>{{end}}</td>{{end}}
</tr>{{else}}<tr><td class="muted">(no zones)</td></tr>{{end}}
</tbody></table>
{{if .Checked}}<div class="muted" style="font-size:.72rem;margin-top:.3rem">live NS check: <span class="ok">✓ serial</span> = all nameservers agree · <span class="err">✗ mismatch</span> = a secondary is out of sync · <a href="/zones?check=1">re-check</a> · <a href="/zones">clear</a></div>
{{else}}<div style="font-size:.78rem;margin-top:.3rem"><a href="/zones?check=1">▸ check nameservers live</a> <span class="muted">(probe every zone's NS for serial agreement)</span></div>{{end}}
{{if .Builtin}}<div class="muted" style="font-size:.72rem;margin-top:.3rem">(+ {{.Builtin}} built-in empty zones hidden; <code>goddns zones -all</code> on the CLI to show)</div>{{end}}

<h2>TSIG keys</h2>
<table><thead><tr><th>key</th><th>algorithm</th></tr></thead><tbody>
{{range .Keys}}<tr><td>{{.Name}}</td><td class="muted">{{.Algorithm}}</td></tr>
{{else}}<tr><td colspan="2" class="muted">(none)</td></tr>{{end}}
</tbody></table>
<div class="muted" style="font-size:.72rem;margin-top:.3rem">secrets are never read into this page</div>

<h2>checks</h2>
<div class="card">
{{range .Findings}}<div class="{{if eq .Class "ok"}}ok{{else if eq .Class "error"}}err{{else if eq .Class "warn"}}warn{{else}}muted{{end}}" style="padding:.15rem 0">{{.Mark}} {{if .Zone}}<b>{{.Zone}}</b>: {{end}}{{.Message}}</div>
{{else}}<div class="muted">(nothing to report)</div>{{end}}
</div>
{{end}}
</main></body></html>{{end}}

{{define "zoneview"}}{{template "head" .}}{{template "topbar" .}}
<div class="subnav"><a href="/zones">&larr; zones</a><span class="here">{{.Name}}</span><span class="muted">read-only</span><span class="sp"></span><a href="/zone?name={{.Name}}&amp;history=1">history</a><a href="/zone?name={{.Name}}">refresh</a></div>
<main>
{{if .Error}}
<div class="card" style="border-color:#5a2230">
<div class="warn">Couldn't transfer <b>{{.Name}}</b> from BIND:</div>
<pre style="margin:.5rem 0">{{.Error}}</pre>
<div class="muted" style="font-size:.8rem">If this is REFUSED, the live view uses AXFR (zone transfer) and the server isn't
allowing it. Add this once in BIND (covers every zone), then refresh:<br>
&nbsp;&nbsp;<code>options { ... allow-transfer { localhost; }; };</code> &nbsp;or key-only:
&nbsp;<code>allow-transfer { key "ddns-update."; };</code><br>
This page never edits BIND — it only reads.</div>
</div>
{{else}}

<h2>{{.Name}}
{{if .InConf}}{{if .Dynamic}}<span class="ok" style="font-size:.8rem">{{.Kind}}</span>{{else}}<span class="muted" style="font-size:.8rem">{{.Kind}}</span>{{end}}{{else}}<span class="muted" style="font-size:.8rem">(not in named.conf)</span>{{end}}</h2>
<div class="card" style="font-size:.84rem">
{{if .Serial}}<div>serial <b>{{.Serial}}</b>{{if .Primary}} &middot; primary {{.Primary}}{{end}} &middot; {{.Count}} records{{if .Signed}} &middot; <span class="warn">DNSSEC-signed</span>{{end}}</div>{{else}}<div>{{.Count}} records</div>{{end}}
{{if .Signed}}<div class="warn" style="margin-top:.3rem;font-size:.8rem">DNSSEC-signed ({{.SignedCount}} signing records). RRSIG/DNSKEY/NSEC are managed by BIND and expire — an <code>-export</code> dump of them is not a hand-restorable backup; restore the unsigned source and let BIND re-sign.</div>{{end}}
{{if .InConf}}{{if .Dynamic}}<div class="ok" style="margin-top:.3rem">DYNAMIC — updated live{{if .Keys}} via key(s): {{.Keys}}{{end}}. The records below are journal-merged (what BIND actually serves), so you don't need to freeze/thaw to see them.</div>
{{else if .FileEdit}}<div class="ok" style="margin-top:.3rem">static — enabled for in-place editing. goddns rewrites only the changed line(s) (comments/formatting kept), checkzones, backs up and reloads — and coexists with your <code>nano</code> edits (a concurrent change is refused, not clobbered).</div>
{{else}}<div class="muted" style="margin-top:.3rem">static — edited by hand in the zone file (nano &rarr; serial+1 &rarr; rndc reload).</div>{{end}}{{end}}
</div>

<table><thead><tr><th>name</th><th>TTL</th><th>type</th><th>data</th>{{if .Editable}}<th></th>{{end}}</tr></thead><tbody>
{{range .Records}}<tr>
<td>{{.Name}}</td><td class="muted">{{.TTL}}</td>
<td>{{.Type}}</td><td style="word-break:break-all">{{.Data}}</td>
{{if $.Editable}}<td style="white-space:nowrap"><form class="inline" method="post" action="/zone/record"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="zone" value="{{$.Name}}"><input type="hidden" name="action" value="del"><input type="hidden" name="rr" value="{{.Full}}"><button class="danger" type="submit">del</button></form></td>{{end}}
</tr>{{else}}<tr><td colspan="{{if .Editable}}5{{else}}4{{end}}" class="muted">(no records)</td></tr>{{end}}
</tbody></table>
{{if .Editable}}
<div class="card"><form method="post" action="/zone/record"><div class="row">
<input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="zone" value="{{.Name}}"><input type="hidden" name="action" value="add">
<div style="flex:1"><label>add record (zone-file line)</label><input name="rr" placeholder="host.{{.Name}}. 60 IN A 203.0.113.9" style="width:100%"></div>
<div><button type="submit">add</button></div>
</div></form>
<div class="muted" style="font-size:.72rem">{{if .FileEdit}}static zone — del/add rewrite the file in place (surgical), checkzone + backup + rndc reload, with a confirm + diff. Raw whole-file edits stay on the CLI (<code>goddns zone edit</code>).{{else}}dynamic zone — edits go via a signed RFC2136 UPDATE, snapshotted first; del/add show a confirm + diff. The key's update-policy is the hard bound.{{end}}</div></div>
{{end}}
<div class="muted" style="font-size:.72rem;margin-top:.4rem">live via AXFR ({{.Auth}}). CLI: <code>goddns zone {{.Name}}</code> / <code>goddns record …</code>.</div>

<h2>SOA / NS checks</h2>
<div class="card">
{{range .Delegation}}<div class="{{if eq .Class "ok"}}ok{{else if eq .Class "error"}}err{{else if eq .Class "warn"}}warn{{else}}muted{{end}}" style="padding:.15rem 0">{{.Mark}} {{.Message}}</div>
{{else}}<div class="muted">(no NS findings)</div>{{end}}
</div>

{{if .Checked}}
<h2>nameservers <span class="muted">(live)</span></h2>
<table><thead><tr><th>NS</th><th>address</th><th>serial</th><th>status</th></tr></thead><tbody>
{{range .NS}}<tr>
<td>{{.Name}}</td><td class="muted">{{if .Addr}}{{.Addr}}{{else}}—{{end}}</td>
<td>{{if .Serial}}{{.Serial}}{{else}}<span class="muted">—</span>{{end}}</td>
<td>{{if .OK}}<span class="ok">ok</span>{{else}}<span class="warn">{{if .Note}}{{.Note}}{{else}}?{{end}}</span>{{end}}</td>
</tr>{{else}}<tr><td colspan="4" class="muted">(no nameservers)</td></tr>{{end}}
</tbody></table>
{{if .NoAuth}}<div class="warn" style="margin-top:.3rem">⚠ no nameserver answered authoritatively</div>
{{else if .Agree}}<div class="ok" style="margin-top:.3rem">✓ all nameservers agree on the serial</div>
{{else}}<div class="err" style="margin-top:.3rem">✗ serial MISMATCH across nameservers — a secondary is out of sync</div>{{end}}
{{else}}
<p style="margin-top:.6rem"><a href="/zone?name={{.Name}}&amp;check=1">▸ check nameservers live (probe each NS for the serial it serves)</a></p>
{{end}}
{{end}}
</main></body></html>{{end}}

{{define "zonehist"}}{{template "head" .}}{{template "topbar" .}}
<div class="subnav"><a href="/zones">&larr; zones</a><a href="/zone?name={{.Name}}">{{.Name}}</a><span class="here">history</span><span class="sp"></span><a href="/zone?name={{.Name}}&amp;history=1">refresh</a></div>
<main>
{{if .Error}}<div class="card" style="border-color:#5a2230"><pre style="margin:.5rem 0">{{.Error}}</pre></div>
{{else}}

{{if .HasDiff}}<h2>latest change <span class="muted">serial {{.FromSerial}} &rarr; {{.ToSerial}}</span></h2>
<pre>{{range .Removed}}<span class="err">- {{.}}</span>
{{end}}{{range .Added}}<span class="ok">+ {{.}}</span>
{{end}}{{if and (not .Removed) (not .Added)}}<span class="muted">(no record changes; serial bumped only)</span>{{end}}</pre>
{{end}}

<h2>snapshots</h2>
<table><thead><tr><th>serial</th><th>captured</th>{{if .Editable}}<th></th>{{end}}</tr></thead><tbody>
{{range .Snaps}}<tr><td>{{.Serial}}</td><td class="muted">{{.Taken}}</td>{{if $.Editable}}<td><form method="post" action="/zone/restore" style="margin:0">
<input type="hidden" name="csrf" value="{{$.CSRF}}">
<input type="hidden" name="zone" value="{{$.Name}}">
<input type="hidden" name="id" value="{{.ID}}">
<button type="submit">restore</button></form></td>{{end}}</tr>
{{else}}<tr><td colspan="{{if .Editable}}3{{else}}2{{end}}" class="muted">(no snapshots yet — the serve loop captures them on SOA-serial change)</td></tr>{{end}}
</tbody></table>
{{if .Editable}}<div class="muted" style="font-size:.72rem;margin-top:.4rem">restore re-creates a snapshot's records as a new change (the SOA serial moves forward; DNSSEC stays with BIND). The restore is itself snapshotted, so it is undoable.</div>{{end}}
<div class="muted" style="font-size:.72rem;margin-top:.4rem">CLI: <code>goddns zone {{.Name}} -history</code> / <code>-diff</code>{{if .Editable}} / <code>goddns record restore {{.Name}} &lt;id&gt;</code>{{end}}.</div>
{{end}}
</main></body></html>{{end}}

{{define "recordconfirm"}}{{template "head" .}}
<header><div><span class="b">goddns admin</span> <span class="muted">confirm</span></div>
<div><a href="/zone?name={{.Zone}}">cancel</a></div></header>
<main><h2>{{.Action}} record in {{.Zone}}</h2>
<div class="card">
<pre>{{range .Removed}}<span class="err">- {{.}}</span>
{{end}}{{range .Added}}<span class="ok">+ {{.}}</span>
{{end}}{{if and (not .Removed) (not .Added)}}<span class="muted">(nothing would change)</span>{{end}}</pre>
<form method="post" action="/zone/record">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<input type="hidden" name="zone" value="{{.Zone}}">
<input type="hidden" name="action" value="{{.Action}}">
<input type="hidden" name="rr" value="{{.RR}}">
<input type="hidden" name="confirm" value="1">
<button class="{{if .Removed}}danger{{end}}" type="submit">apply</button>
<a href="/zone?name={{.Zone}}" style="margin-left:1rem;color:#9aa4b2">cancel</a>
</form></div></main></body></html>{{end}}

{{define "restoreconfirm"}}{{template "head" .}}
<header><div><span class="b">goddns admin</span> <span class="muted">confirm restore</span></div>
<div><a href="/zone?name={{.Zone}}&amp;history=1">cancel</a></div></header>
<main><h2>restore {{.Zone}} to snapshot #{{.ID}} <span class="muted">serial {{.Serial}} &middot; {{.Taken}}</span></h2>
<div class="card">
<pre>{{range .Removed}}<span class="err">- {{.}}</span>
{{end}}{{range .Added}}<span class="ok">+ {{.}}</span>
{{end}}</pre>
<div class="muted" style="font-size:.72rem">SOA &amp; DNSSEC are left to BIND — the serial moves forward and this restore is itself snapshotted (undoable).</div>
<form method="post" action="/zone/restore">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<input type="hidden" name="zone" value="{{.Zone}}">
<input type="hidden" name="id" value="{{.ID}}">
<input type="hidden" name="confirm" value="1">
<button class="{{if .Removed}}danger{{end}}" type="submit">restore</button>
<a href="/zone?name={{.Zone}}&amp;history=1" style="margin-left:1rem;color:#9aa4b2">cancel</a>
</form></div></main></body></html>{{end}}

{{define "logs"}}{{template "head" .}}{{template "topbar" .}}
<div class="subnav">
<a href="/logs?which=access" {{if eq .Which "access"}}class="here"{{end}}>access log</a>
<a href="/logs?which=event" {{if eq .Which "event"}}class="here"{{end}}>event log</a>
<span class="sp"></span><a href="/logs?which={{.Which}}">refresh</a></div>
<main><h2>{{.Title}} <span class="muted">(newest first, last 300)</span></h2>
<pre>{{range .Lines}}{{.}}
{{end}}</pre></main></body></html>{{end}}

{{define "passwd"}}{{template "head" .}}{{template "topbar" .}}
<div class="subnav"><span class="here">password hash</span><span class="sp"></span></div>
<main><h2>generate a password hash</h2>
{{if .Error}}<div class="card" style="border-color:#5a2230;color:#ff8aa6">{{.Error}}</div>{{end}}
{{if .Entry}}<div class="card">
<div class="muted">bcrypt entry for <b>{{.U}}</b> — paste into <code>[admin] users</code> in goddns.conf, or a vhost's <code>basic_auth</code>:</div>
<div class="tok">{{.Entry}}</div>
<div class="warn" style="font-size:.78rem;margin-top:.5rem">goddns never rewrites your goddns.conf — paste this yourself; it hot-reloads. (For a proxy vhost you can skip this and just type the password in the vhost form.)</div>
</div>{{end}}
<div class="card"><form method="post" action="/passwd">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<div><label>user</label><input name="u" value="{{.U}}" autocomplete="off" style="width:100%"></div>
<div style="margin-top:.6rem"><label>password</label><input name="pw" type="password" autocomplete="new-password" style="width:100%"></div>
<div style="margin-top:.8rem"><button type="submit">generate hash</button></div>
</form></div>
<div class="muted" style="font-size:.72rem">Same as <code>goddns passwd -user …</code> on the console — bcrypt, computed here so you don't need shell access. The password is never stored or logged.</div>
</main></body></html>{{end}}
`
