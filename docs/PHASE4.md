# Phase 4 — goddns-owned zones (design)

Status: **proposal, for sign-off.** Phases 1–2 shipped (read-only history/diff;
the audited, reversible write layer: record CRUD on dynamic zones, snapshot
rollback, TSIG rotation, proxy-vhost CRUD). Phase 4 adds a **new zone ownership
category** so goddns can do full record CRUD — plus import/export and zone
lifecycle — on zones the operator **explicitly hands to it**, with managed
serials and `named-checkzone` before every write. This is the panel-backend /
"own your authoritative DNS" direction. This document is the architecture we
build to, so the pieces land coherently.

## 0. The line we're crossing — and the line we're NOT

The hard invariant has been: *goddns never changes a zone's ownership model.*
Phase 4 does **not** weaken it — it adds a **fourth branch**. A zone is exactly
one of:

| Category | Source of truth | goddns does |
|---|---|---|
| **dynamic** (RFC2136) | named's journal + file | sends signed `UPDATE` (today) |
| **goddns-owned** (NEW) | goddns's store (SQLite) | renders + owns the zone file |
| hand-edited static | the operator's zone file | **read-only** (diff/history only) |
| panel (cPanel/DA/Virtualmin) | the panel | **read-only** (panel API is its own track) |

goddns still **never** touches a hand-edited static zone, a panel zone, or a
dynamic zone's file. It writes a zone file **only** when that zone is explicitly
goddns-owned, and a zone becomes owned **only** by an operator-confirmed action
(`create` / `adopt`). One owner per zone, always; goddns refuses to file-edit a
dynamic zone (use UPDATE) and to UPDATE an owned zone (re-render).

Why a separate model instead of "just edit the static file in place": rewriting
a hand-edited file loses the operator's comments/formatting/ordering, forces a
serial-bump + `checkzone` + reload dance, and collides with panel ownership —
exactly what the invariant exists to prevent. "Edit records with a correctly
managed serial" is what dynamic update gives for free; goddns-owned zones give
the same guarantee for zones the operator wants goddns, not named's journal, to
be the canonical source for.

## 1. Source of truth: the store

Two new SQLite tables (alongside the existing `records` token store and Phase-1
`snapshots`):

- `owned_zones` — apex params per owned zone: SOA (primary, mailbox, refresh/
  retry/expire/min-TTL), `$TTL`, current serial, dnssec mode, created/updated.
- `zone_records` — `(zone, name, ttl, type, rdata)` rows; the canonical record
  set goddns renders from.

Owned zones' truth lives here; dynamic zones' truth stays in named's journal
(goddns never stores those). Clean separation, no double-bookkeeping.

## 2. Detection — how goddns knows a zone is "owned"

A zone is goddns-owned iff its `file` path resolves under goddns's zone
directory (proposed `/var/lib/goddns/zones/`) **and** the file carries the
goddns canonical header marker (a `; goddns-owned` comment line the renderer
always emits). Both conditions guard against a hand-moved file or a path
collision. `named.Zone` grows an `Owned bool`; `Kind()` returns `"managed"`.
The classification is best-effort and fail-safe: if in doubt, treat as
read-only, never as owned.

## 3. The write pipeline (reuses the Phase-2 backbone)

Every owned-zone change flows through the same
`Authorize → Validate → Preview(diff) → Snapshot → Apply → Audit → Verify →
Rollback` pipeline as Phase 2, with the **Apply** stage being the new bit:

```
mutate store rows → render canonical zone file → named-checkzone (HARD GATE)
   → atomic write into the goddns zone dir → rndc reload <zone> → verify
```

- **Render** — deterministic zone file: `$TTL`, SOA with the managed serial, the
  apex NS set, then records sorted the way `named.SortZone` already orders them.
  One canonical format (an extension of `named.Canonical` to a full zone file
  with directives + the `; goddns-owned` marker).
- **Serial** — goddns owns it. Date-based `YYYYMMDDnn` with a **monotonic guard**
  (always strictly greater than the stored serial; never moves backward, so
  secondaries always converge). The serial lives in `owned_zones`, not parsed
  back out of the file.
- **Validate** — `named-checkzone <zone> <tmpfile>` **must** pass before the file
  is published. goddns never writes a zone named would reject — a bad render can
  never take the zone down. (Same shell-out discipline as `rndc reconfig` in
  `rotate-key` and `named-checkconf` in the viewer.)
- **Apply** — atomic temp + rename + fsync into the goddns zone dir (goddns owns
  it, like `proxy.d/` fragments), then `rndc reload <zone>` (per-zone blast
  radius).
- **Verify** — re-query post-reload: serial bumped + a sentinel record resolves.
- **Snapshot + Rollback** — Phase-1 AXFR snapshots already work (owned zones are
  transferable). Rollback re-imports a chosen snapshot's records into the store
  and re-renders — i.e. the existing `record restore` model, with the filezone
  Mutator instead of UPDATE. The restore is itself snapshotted (undoable).

## 4. The Mutator abstraction — reuse, not reinvent

`ddns.Mutator` (`Apply(zone string, ops []Op)`) already abstracts "how a write
reaches the zone", with one implementation (`RFC2136`). Phase 4 adds a **second
implementation** — `filezone` — that applies the same `Op`s (AddRR / DelRR /
DelRRset / DelName) to the **store**, then renders + checkzones + reloads.

`recordmut`'s pipeline (validate → preview/diff → confirm → snapshot → apply →
audit) becomes **backend-agnostic**: it selects the Mutator by zone ownership —
dynamic → `RFC2136`, owned → `filezone`. The record-editing CLI and admin UI we
already shipped then work on owned zones with minimal change. This is the payoff:
the `Op` model maps cleanly onto store mutations, so most of Phase 4's record
CRUD is *wiring*, not new surface.

## 5. Zone lifecycle — create / adopt / import / export / delete

- **export** — render the store → a zone file (download in the UI / stdout in the
  CLI). The AXFR-based `-export` we have already covers the read side; this adds
  the store-render path for owned zones.
- **import** — parse a BIND zone file (miekg `dns.ZoneParser`) → records into the
  store → render + checkzone + reload. The on-ramp for "bring my existing zone
  under goddns".
- **adopt** (static → owned, the migration) — read the live zone (AXFR), load its
  records into the store, render goddns's canonical version, `checkzone`, and
  show a **diff vs the live zone to prove nothing is lost**. On confirm, point the
  zone's `file` at goddns's copy and reload. Caveats surfaced up front: comments/
  formatting are not preserved (goddns owns the content now), and the hand-edit/
  `nano → serial+1 → rndc reload` habit ends for that zone.
- **create** — a brand-new owned zone (SOA/NS from flags or sane defaults) →
  render → checkzone → write file → emit the named.conf glue.
- **delete** — remove the zone file + the named.conf glue + `rndc reconfig`,
  store rows archived (recoverable).

### named.conf glue — the one place the invariant needs a decision

A goddns-owned zone needs a `zone "x" { type master; file "..."; };` stanza in
named.conf. Per the invariant goddns **never writes named.conf**. Two models
(open question §8):

1. **(recommended) a goddns-owned `zones.d/*.conf` fragment dir**, `include`d once
   by named.conf — the exact `tsig.keys` / `proxy.d/` pattern. goddns writes the
   zone-config fragment + `rndc reconfig`. The operator opts in by adding **one**
   include line, and in doing so consents to goddns declaring/removing master
   zones (a real, named privilege — see §6).
2. **(conservative)** goddns prints the `zone{}` stanza; the operator pastes it
   into named.conf by hand. No blanket power; more friction.

The recommendation: ship the fragment dir for convenience, **but gate zone
create/delete (the lifecycle that touches the fragment dir) to the root CLI** —
the daemon never declares or removes zones (§6).

## 6. Risk surface & the daemon/CLI privilege split (the important part)

goddns now writes zone-data files, runs `rndc reload/reconfig`, and (via the
fragment dir) can declare master zones. A compromised internet-facing daemon
must not be able to hijack DNS. The control is a **privilege split**:

- **Zone lifecycle — create / delete / adopt / import a *new* zone, and any write
  to the named.conf fragment dir — is CLI-only, run by root.** The daemon and the
  admin UI **cannot** create, delete, or declare zones.
- **Record CRUD *within an already-owned zone* — daemon / admin-UI allowed**, the
  same trust level as editing a dynamic zone today. Bounded to the set of zones
  the operator already created; it can never make named authoritative for a new
  name.

Layered on top:

- **`named-checkzone` is a hard gate** — goddns never publishes a zone named would
  reject, so a bad render can't take a zone down; reloads are per-zone.
- **Every change is snapshotted** — a bad edit is one `restore` away.
- **File access**: record CRUD by the daemon means the daemon writes the owned
  zone's file. Two options to weigh at build time (§8): **(a)** daemon writes the
  file directly (needs write to the zone dir, like `proxy.d/` — setgid, group
  `goddns`, `0640` files); **(b)** daemon writes the **store only**, and a small
  privileged renderer (root, triggered via a queue/socket) does the file write +
  reload. (b) is tighter (the daemon never touches `/var/named`-class files) at
  the cost of more moving parts. The doc leans **(a)** for symmetry with the rest
  of goddns, with the zone dir kept out of any path a hand-static zone uses.

## 7. Interaction with what's already shipped

- **History / snapshots / rollback** — work unchanged (AXFR-based; owned zones are
  transferable). Rollback re-renders from a snapshot.
- **Record editor (CLI + admin)** — reused via the `filezone` Mutator; owned zones
  gain the same add/del/edit/restore UX as dynamic zones.
- **Zones viewer** — owned zones show as kind `managed`, with edit controls and
  import/export.
- **Dynamic zones, proxy, DDNS tokens, TSIG keyring** — untouched.
- Implements the long-standing `BACKLOG.md` "Phase 4 — Platform: backends" item
  for the self-hosted (non-panel) case.

## 8. Open questions for sign-off

1. **named.conf glue**: blanket `include zones.d/` (convenient, lets goddns manage
   the zone list) vs per-zone manual paste (conservative)? *Recommendation:*
   fragment dir, with create/delete CLI-only.
2. **Daemon file access**: daemon writes the zone file directly (a) vs store-only +
   a privileged render helper (b)? *Recommendation:* (a), unless you want the
   daemon fully out of `/var/named`.
3. **Zone dir**: `/var/lib/goddns/zones/` (data, daemon-writable) vs
   `/etc/goddns/zones.d/` (config-adjacent)?
4. **Serial scheme**: date-based `YYYYMMDDnn` (human-readable) vs unixtime vs plain
   increment? *Recommendation:* date-based with the monotonic guard.
5. **DNSSEC**: goddns manages the **unsigned** zone only and never writes
   RRSIG/DNSKEY/NSEC\* (the same exclusion as `record restore`'s `managed()`);
   named's `dnssec-policy` / inline-signing signs on top and owns the signed
   serial. *Recommendation:* confirm this; ship unsigned owned zones first, signed
   via inline-signing as a later stage (needs interop testing on serial
   coordination + reload semantics).

## 9. Staged build (independent review per step, as in Phase 2)

- **Stage 0** — store schema (`owned_zones` + `zone_records`), the canonical zone
  renderer, and the `named-checkzone` validator. Pure and testable; writes
  nothing live.
- **Stage 1** — the `filezone` Mutator (store → render → checkzone → atomic write
  → `rndc reload` → verify) behind `ddns.Mutator`; route `recordmut` to pick the
  backend by ownership; CLI record CRUD on an owned zone.
- **Stage 2** — zone lifecycle: `create` / `delete` + the named.conf fragment glue,
  CLI/root-only; the privilege split enforced.
- **Stage 3** — `adopt` / `import` (zone-file parse → store, diff vs live, the
  migration path) + store-render `export`.
- **Stage 4** — admin UI: owned-zone record CRUD (reuse the record editor),
  import/export buttons; the daemon never crosses into zone lifecycle.
- **Stage 5** — DNSSEC interop (inline-signing), signed owned zones.

Each stage: design-conformant, snapshot-before, `checkzone`-gated, independently
reviewed, squash-merged — same rhythm that carried Phase 2.
