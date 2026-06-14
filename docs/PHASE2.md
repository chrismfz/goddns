# Phase 2 — the write layer (design)

Status: **proposal, for sign-off.** Phase 1 (read-only history/diff) shipped.
Phase 2 turns goddns from read-only-introspection-plus-DDNS into a deliberate,
audited, **reversible** write layer. This document is the architecture we build
to, so the pieces land as a coherent whole instead of ad hoc.

## 0. Principles (carried from the roadmap)

1. **Read-only is the default; every write is deliberate, audited, reversible.**
2. **The invariant — goddns never changes a zone's ownership model.** It detects
   who owns a zone and uses the matching mechanism, or refuses:
   - dynamic zone → RFC 2136 `UPDATE` (scoped by `update-policy`);
   - panel-managed zone (cPanel/DirectAdmin/Virtualmin) → the panel's API (Phase 4);
   - hand-edited static zone → read-only (diff/history only, no auto-apply).
3. **Phase 1 history is the undo.** Nothing in Phase 2 ships without a snapshot
   taken immediately before the change, so every write is one click from rollback.

## 1. The mutation pipeline (the backbone)

Every Phase 2 write — a DNS record edit, a TSIG key rotation, a proxy vhost
change — flows through ONE pipeline, so the safety machinery is shared and
uniform rather than re-implemented per feature:

```
Authorize → Validate → Preview (diff) + Confirm → Snapshot → Apply → Audit → Verify
                                                                          └→ Rollback
```

| Stage | What | Reuses |
|---|---|---|
| Authorize | admin session + CIDR + optional Basic (later: per-tenant RBAC) | `internal/admin` auth layers |
| Validate | the requested change is well-formed and permitted (e.g. zone is dynamic) | per-mutation validators |
| Preview + Confirm | show a diff of current → proposed; require an explicit confirm | the no-JS confirm + CSRF pattern (token delete) |
| Snapshot | capture current state before applying | Phase-1 `store` snapshots (zones); fragment copy (vhosts) |
| Apply | execute via the owner-correct mechanism | `ddns` UPDATE / atomic file write / key-file rewrite |
| Audit | structured log line: who, what, when, from where | `Handler.audit` |
| Verify | re-read and confirm the change took (and re-snapshot) | AXFR / re-stat |
| Rollback | re-apply a prior snapshot through the same Apply path | Phase-1 history + Apply |

A small `internal/mutate` helper encodes this flow; each mutation type plugs in a
validator + an apply func. We don't build the abstraction up front in the
abstract — it emerges from the first two features and is generalised as more land.

## 2. The write Backend abstraction (the key technical change)

Today `ddns.Backend` is DDNS-shaped:

```go
type Backend interface { Update(fqdn, zone string, ip net.IP, ttl uint32) error }
```

Generalise it to apply a **set of record operations** in one signed UPDATE, so
arbitrary CRUD (MX/TXT/CNAME/SRV/…) shares the path and the panel-backend seam
stays intact:

```go
type Op struct {
    Action  Action  // AddRR | DelRR | DelRRset(name,type) | DelName(name)
    RR      dns.RR  // the record (for AddRR/DelRR); header name/type for the Del* forms
}

type Mutator interface {
    Apply(zone string, ops []Op) error   // one atomic RFC2136 UPDATE (or panel API call)
}
```

The existing `Update(fqdn,zone,ip,ttl)` becomes a thin caller of `Apply`
(`DelRRset A`, `DelRRset AAAA`, `AddRR A/AAAA`). A future `cpanel` Mutator
implements `Apply` via whmapi1 — same interface, honouring the invariant.

## 3. Mutation types

### 2A.1 — `rotate-key` (smallest; timely)
Rotate goddns's **own** TSIG secret: generate a new base64 secret, rewrite its
dedicated key include file (same key name), update goddns's own config/env,
`rndc reconfig`, self-test an UPDATE. Self-contained (goddns owns both ends),
scoped write to one key file — not `named.conf`. Mirrors the DDNS token-rotate
philosophy one layer down. (Already sketched in BACKLOG.)

### 2A.2 — BIND record CRUD (dynamic zones only)
Add / edit / delete any RR type via `Mutator.Apply`. Gated to dynamic zones (the
zone classifier already exists); **refuses** on static/panel zones per the
invariant, pointing the operator at the panel backend or an explicit conversion.
Every write: validate → diff-preview vs the live AXFR → confirm → auto-snapshot →
Apply → audit → re-AXFR verify. Blast radius bounded by the key's `update-policy`.

### 2A.3 — Rollback (the keystone tying Phase 1 ↔ Phase 2)
`restore(zone, snapshotID)`: fetch the snapshot's canonical records, AXFR the
live zone, compute the diff, and — **for a dynamic zone** — apply the delta
(dels + adds) via `Apply`, then re-snapshot. For static/panel zones rollback is
**diff-only**: show exactly what to revert; the operator applies it their way
(invariant). This is the full answer to "a client broke their DKIM/SPF/DMARC/MX":
see the diff (Phase 1), one-click restore (2A.3) when the zone is dynamic.

### 2B.1 — proxy vhost CRUD (write `proxy.d/` fragments)
The write half of what shipped read-only. add/edit/delete a vhost from the admin
UI/CLI by writing a `proxy.d/<name>.conf` fragment **atomically** (temp + rename),
never touching the hand-authored `goddns.conf`. Validate the fragment by loading
it (the existing merge already rejects dupes/typos), then the reload poll (which
now watches `proxy.d/`) applies it. Simplest trust model — no BIND, no invariant.

### 2B.2 — tunnels (later, with `goddns tunnel`)
Tunnel definitions are token-shaped (name + token + target) → SQLite, tokens-style
CRUD from day one. Built together with the `goddns tunnel` reverse-tunnel feature.

## 4. Security model

- **Auth**: the existing admin stack (CIDR → Basic → session); Phase 4 adds RBAC.
- **CSRF + confirm**: every mutating endpoint is POST + CSRF-checked and shows a
  diff-preview/confirm step (the pattern already used for token delete/rotate).
- **Audit**: one structured `admin-audit` line per write (user, peer, action, target).
- **Snapshot-before**: no write without a fresh Phase-1 snapshot first.
- **Scope**: BIND writes bounded by `update-policy`; a separate, more-restricted
  TSIG key for admin-initiated edits vs the DDNS key is an option to keep blast
  radius small. The daemon still never gains write to `named.conf` or zone files.
- **Refusal**: writes to non-dynamic zones are refused with a clear message, never
  "helpfully" made to work.

## 5. Build sequence (one reviewed PR each)

1. **Backbone**: generalise `ddns.Backend` → `Mutator.Apply(zone, ops)`; the
   DDNS path becomes a caller. No user-facing change; pure seam. (small, low-risk)
2. **`rotate-key`** (CLI + admin) — exercises the pipeline end-to-end on the
   smallest mutation; timely (the ddns-update key leaked earlier this work).
3. **Record CRUD** (add/edit/delete RR, dynamic-zone-gated) with diff-preview +
   confirm + auto-snapshot.
4. **Rollback** (restore a snapshot) — connects Phase 1 history to 2A.
5. **Vhost CRUD** (write `proxy.d/` fragments) — completes 2B.
6. **Tunnels** — later, with `goddns tunnel`.

Each PR: read-only-by-default elsewhere, behind admin auth, with the snapshot +
audit + confirm machinery, and an independent review before merge.

## 6. Open decisions (recommendations; adjust at sign-off)

- **Rollback apply scope** → dynamic zones only (apply via UPDATE); static/panel
  zones get diff-only restore. (Follows from the invariant.)
- **Admin-edit key** → reuse the DDNS key initially; add a separate scoped key as
  a follow-up if blast radius matters for your deployment.
- **Surface** → both CLI and admin UI for every mutation (project convention).
- **Sequence** → as in §5 (backbone → rotate-key → record CRUD → rollback → vhost).
