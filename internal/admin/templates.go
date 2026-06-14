package admin

import (
	"html/template"
	"log"
	"net/http"
)

const (
	loginTmpl    = "login"
	dashTmpl     = "dash"
	resultTmpl   = "result"
	logsTmpl     = "logs"
	confirmTmpl  = "confirm"
	helpTmpl     = "help"
	zonesTmpl    = "zones"
	zoneViewTmpl = "zoneview"
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

{{define "dash"}}{{template "head" .}}
<header><div><span class="b">goddns admin</span> <span class="muted">{{.Version}}</span></div>
<div><span class="muted">{{.User}}</span><a href="/zones">zones</a><a href="/logs?which=access">access log</a><a href="/logs?which=event">event log</a><a href="/logout">logout</a></div></header>
<main>

<h2>DDNS records</h2>
<table><thead><tr><th>FQDN</th><th>zone</th><th>TTL</th><th>last IP</th><th>last seen</th><th>state</th><th></th></tr></thead><tbody>
{{range .Records}}<tr>
<td>{{.FQDN}}</td><td class="muted">{{.Zone}}</td><td>{{.TTL}}</td>
<td>{{if .LastIP}}{{.LastIP}}{{else}}<span class="muted">—</span>{{end}}</td>
<td class="muted">{{.LastSeen}}</td>
<td>{{if eq .State "enabled"}}<span class="ok">{{.State}}</span>{{else}}<span class="warn">{{.State}}</span>{{end}}</td>
<td style="white-space:nowrap">
<a href="/ddns/help?fqdn={{.FQDN}}">help</a>
<form class="inline" method="post" action="/ddns/rotate"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="fqdn" value="{{.FQDN}}"><button type="submit">rotate</button></form>
<form class="inline" method="post" action="/ddns/del"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="fqdn" value="{{.FQDN}}"><button class="danger" type="submit">delete</button></form>
</td>
</tr>{{else}}<tr><td colspan="7" class="muted">(no records)</td></tr>{{end}}
</tbody></table>

<div class="card"><form method="post" action="/ddns/add"><div class="row">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<div><label>fqdn</label><input name="fqdn" placeholder="home.ddns.myip.gr" size="26"></div>
<div><label>zone</label><input name="zone" placeholder="ddns.myip.gr" size="20"></div>
<div><label>ttl</label><input name="ttl" type="number" value="60" size="6" style="width:5rem"></div>
<div><button type="submit">add token</button></div>
</div></form></div>

{{if .ProxyOn}}<h2>proxy hosts</h2>
<table><thead><tr><th>host</th><th>upstream</th><th>allow</th><th>auth</th><th>rate</th></tr></thead><tbody>
{{range .Proxies}}<tr>
<td>{{.Host}}</td><td class="muted">{{.Upstream}}</td>
<td>{{if .Allow}}{{.Allow}}{{else}}<span class="warn">any</span>{{end}}</td>
<td>{{if .Auth}}<span class="ok">basic</span>{{else}}<span class="muted">—</span>{{end}}</td>
<td>{{if .Rate}}{{.Rate}}/s{{else}}<span class="muted">—</span>{{end}}</td>
</tr>{{else}}<tr><td colspan="5" class="muted">(no proxy hosts)</td></tr>{{end}}
</tbody></table>
<div class="muted" style="font-size:.72rem;margin-top:.4rem">proxy hosts are read-only here — edit goddns.conf (hot-reloaded). DDNS records are managed above.</div>
{{end}}

</main></body></html>{{end}}

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

{{define "zones"}}{{template "head" .}}
<header><div><span class="b">goddns admin</span> <span class="muted">zones (read-only)</span></div>
<div><a href="/">&larr; dashboard</a><a href="/zones">refresh</a></div></header>
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
<table><thead><tr>{{if .HasViews}}<th>view</th>{{end}}<th>zone</th><th>kind</th><th>file</th><th>update key(s)</th></tr></thead><tbody>
{{range .Zones}}<tr>
{{if $.HasViews}}<td class="muted">{{if .View}}{{.View}}{{else}}_default{{end}}</td>{{end}}
<td><a href="/zone?name={{.Name}}">{{.Name}}</a></td>
<td>{{if .Dynamic}}<span class="ok">{{.Kind}}</span>{{else}}<span class="muted">{{.Kind}}</span>{{end}}</td>
<td>{{if .File}}{{.File}}{{if .Status}} <span class="{{if eq .Status "missing"}}err{{else if eq .Status "no journal yet"}}warn{{else}}muted{{end}}">({{.Status}})</span>{{end}}{{else}}<span class="muted">—</span>{{end}}</td>
<td>{{if .Keys}}{{.Keys}}{{else}}<span class="muted">—</span>{{end}}</td>
</tr>{{else}}<tr><td class="muted">(no zones)</td></tr>{{end}}
</tbody></table>
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

{{define "zoneview"}}{{template "head" .}}
<header><div><span class="b">goddns admin</span> <span class="muted">zone {{.Name}} (read-only)</span></div>
<div><a href="/zones">&larr; zones</a><a href="/zone?name={{.Name}}">refresh</a></div></header>
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
{{if .Serial}}<div>serial <b>{{.Serial}}</b>{{if .Primary}} &middot; primary {{.Primary}}{{end}} &middot; {{.Count}} records</div>{{else}}<div>{{.Count}} records</div>{{end}}
{{if .InConf}}{{if .Dynamic}}<div class="ok" style="margin-top:.3rem">DYNAMIC — updated live{{if .Keys}} via key(s): {{.Keys}}{{end}}. The records below are journal-merged (what BIND actually serves), so you don't need to freeze/thaw to see them.</div>
{{else}}<div class="muted" style="margin-top:.3rem">static — edited by hand in the zone file (nano &rarr; serial+1 &rarr; rndc reload).</div>{{end}}{{end}}
</div>

<table><thead><tr><th>name</th><th>TTL</th><th>type</th><th>data</th></tr></thead><tbody>
{{range .Records}}<tr>
<td>{{.Name}}</td><td class="muted">{{.TTL}}</td>
<td>{{.Type}}</td><td style="word-break:break-all">{{.Data}}</td>
</tr>{{else}}<tr><td colspan="4" class="muted">(no records)</td></tr>{{end}}
</tbody></table>
<div class="muted" style="font-size:.72rem;margin-top:.4rem">live via AXFR. CLI: <code>goddns zone {{.Name}}</code> (add <code>-export</code> for a backup snapshot). Read-only.</div>
{{end}}
</main></body></html>{{end}}

{{define "logs"}}{{template "head" .}}
<header><div><span class="b">goddns admin</span> <span class="muted">{{.Title}}</span></div>
<div><a href="/">&larr; dashboard</a><a href="/logs?which={{.Which}}">refresh</a></div></header>
<main><h2>{{.Title}} <span class="muted">(newest first, last 300)</span></h2>
<pre>{{range .Lines}}{{.}}
{{end}}</pre></main></body></html>{{end}}
`
