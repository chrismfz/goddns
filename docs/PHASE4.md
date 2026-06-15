# Phase 4 — goddns-owned zones (design)

Status: **proposal, revised after independent design review.** Phases 1–2
shipped (read-only history/diff; the audited, reversible write layer: record
CRUD on dynamic zones, snapshot rollback, TSIG rotation, proxy-vhost CRUD).
Phase 4 adds a **new zone ownership category** so goddns can do full record
CRUD — plus import/export and zone lifecycle — on zones the operator
**explicitly hands to it**, with managed serials and `named-checkzone` before
every write. This is the panel-backend / "own your authoritative DNS"
direction. This document is the architecture we build to, so the pieces land
coherently. The design-review changes are marked **[R]** at the point they
apply.

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
  **[R]** plus `file_path` (the exact path goddns owns and will write — the
  consistency anchor, §2) and `serial_floor` (the live SOA serial captured at
  adopt/import time, so the managed serial can never regress below what
  secondaries already hold, §3).
- `zone_records` — `(zone, name, ttl, type, rdata)` rows; the canonical record
  set goddns renders from. **[R]** rows also carry the last writer's identity
  (cli / daemon-admin) for the audit trail, so a render can surface which rows
  the internet-facing daemon last touched (§6).

Owned zones' truth lives here; dynamic zones' truth stays in named's journal
(goddns never stores those). Clean separation, no double-bookkeeping. **[R]
A row in `owned_zones` is the SOLE authority for "this zone is goddns-owned"
(§2) — the on-disk file and its marker are consistency checks, never the
ownership decision.**

## 2. Authority & detection — how goddns knows a zone is "owned" **[R]**

**The authority is a row in `owned_zones`, full stop.** A zone is goddns-owned
iff goddns recorded it as owned in SQLite — set ONLY by the root CLI
`create`/`adopt` (§5). The on-disk file path and its `; goddns-owned` marker are
**not** the ownership decision (a comment line is self-asserted and forgeable; a
hand-static zone — or a restored backup, or a compromised daemon dropping a
file — could carry the marker and get clobbered). Keying authority on the store
makes false-positive clobber impossible: no row → never owned → never written.

The path + marker become a **tamper tripwire checked immediately before any
write**: goddns confirms the zone's live `file` directive equals the
`file_path` it recorded **and** the existing file still carries the marker, and
**refuses to write if either disagrees** (someone moved/replaced/renamed it out
of band). `named.Zone` gains `Owned bool` (set from the store, not the file);
`Kind()` returns `"managed"`.

Hard refusals at adopt time (state of the world goddns cannot safely own):

- a zone that appears in **more than one view** (`ZoneByName` is first-match;
  ownership across views is ambiguous);
- a `file` that is a **symlink**, or resolves outside the goddns zone dir;
- an on-disk file containing **`$INCLUDE` or `$GENERATE`** (the canonical
  renderer cannot represent them — §5, M3).

The goddns zone dir is a hard precondition checked at startup: it must be a path
**no hand-static zone ever uses**, so a path collision can't even arise.

## 3. The write pipeline (reuses the Phase-2 backbone)

Every owned-zone change flows through the same
`Authorize → Validate → Preview(diff) → Snapshot → Apply → Audit → Verify →
Rollback` pipeline as Phase 2, with the **Apply** stage being the new bit:

```
[R] build candidate record-set (in a store txn) → render → named-checkzone (HARD GATE)
    → commit the txn → atomic write into the goddns zone dir → rndc reload <zone> → verify
    (checkzone fails → roll back the txn; store and file stay in agreement, nothing changed)
```

- **Render** — deterministic zone file: `$TTL`, `$ORIGIN`, SOA with the managed
  serial, the apex NS set, then records sorted the way `named.SortZone` orders
  them, plus the `; goddns-owned` marker. **[R]** This is **new code**, not a
  reuse of `named.Canonical` (which is a record *sorter*, not a zone-file
  renderer — no directives, no owner-name FQDN/relative choice); it needs its
  own test vectors (apex SOA/NS emission, RFC3597 `\#` for unknown types).
- **Serial** — goddns owns it, date-based `YYYYMMDDnn`. **[R]** The monotonic
  guard must **floor on the live serial, not just the stored one**:
  `next = max(store_serial, live_serial, todayNN) + 1`, where `live_serial`
  comes from a cheap SOA query against the local named (which Verify already
  does). This kills three split-brain cases: adopting a zone whose live serial
  already exceeds ours (secondaries would reject a backwards serial), a human/
  panel bumping the file out of band, and inline-signing maintaining its own
  serial axis. On `nn` overflow (>100 changes/day) fall through to
  `live_serial + 1` rather than wrapping/stalling.
- **Validate** — **[R]** `named-checkzone` with explicit strict flags
  (`-k fail -m fail -n fail -i full`), run on the rendered candidate **before
  the store txn commits**. goddns never writes a zone named would reject. But
  checkzone is **necessary, not sufficient** — it passes many semantically
  broken states (dangling NS, missing in-bailiwick glue, broken delegation,
  CNAME-at-apex in lenient modes). So Verify (below) adds a semantic check.
- **Apply** — atomic temp + rename + fsync into the goddns zone dir, `O_NOFOLLOW`,
  **refusing if the target is a symlink** (§6); filename derived solely from the
  `owned_zones` row, never from request input. Then `rndc reload <zone>`
  (per-zone blast radius). **[R]** If `rndc` is unreachable / named is down, the
  write is **failed**: do not leave a new file active without a confirmed reload.
- **Verify** — **[R]** beyond "serial bumped": re-query the live resolver and
  confirm the apex **SOA serial and NS set match what was rendered**, so a
  silently-broken delegation is caught while rollback is still one step. Use the
  apex SOA as the sentinel (no need to inject a record into operator data).
  Recovery on any failure: restore the previous rendered file + `rndc reload`
  (mirrors the `rotate-key` rollback discipline).
- **Snapshot + Rollback** — **[R]** for owned zones, snapshot the **store's
  canonical record set** (what goddns rendered), not the AXFR — that is the
  byte-exact thing to roll back to, and it sidesteps the AXFR≠source mismatch
  (an AXFR of a signed zone carries `managed()` DNSSEC records and named's
  serial). Rollback re-loads that record set into the store and re-renders
  through the same pipeline; the restore is itself snapshotted (undoable). AXFR
  snapshots stay as secondary history for cross-checking.

## 4. The Mutator abstraction — reuse, not reinvent

`ddns.Mutator` (`Apply(zone string, ops []Op)`) already abstracts "how a write
reaches the zone", with one implementation (`RFC2136`). Phase 4 adds a **second
implementation** — `filezone` — that applies the same `Op`s (AddRR / DelRR /
DelRRset / DelName) to the **store**, then renders + checkzones + reloads.

`recordmut`'s pipeline (validate → preview/diff → confirm → snapshot → apply →
audit) becomes **backend-agnostic**: it selects the Mutator by zone ownership —
dynamic → `RFC2136`, owned → `filezone`. The record-editing CLI and admin UI we
already shipped then work on owned zones with minimal change. This is the payoff:
the `Op` model maps cleanly onto store mutations (`DelRRset`/`DelName`/exact
`DelRR` are all expressible as scoped SQL deletes; `buildResult` already resolves
them against a record set).

**[R] The one real mismatch to respect:** `RFC2136.Apply` is **one atomic signed
transaction**; `filezone` is a multi-step pipeline (mutate → render → checkzone →
write → reload) that can fail partway. The resolution is the §3 ordering:
render + checkzone happen on a **candidate** record-set inside a store
transaction that **commits only after checkzone passes**. So "the store and the
live file always agree" is an enforced invariant, not a hope — a checkzone
failure rolls the transaction back and nothing changed.

## 5. Zone lifecycle — create / adopt / import / export / delete

- **export** — render the store → a zone file (download in the UI / stdout in the
  CLI). The AXFR-based `-export` we have already covers the read side; this adds
  the store-render path for owned zones.
- **import** — parse a BIND zone file (miekg `dns.ZoneParser`) → records into the
  store → render + checkzone + reload. The on-ramp for "bring my existing zone
  under goddns".
- **adopt** (static → owned, the migration) — read the live zone (AXFR), load its
  records into the store, render goddns's canonical version, `checkzone`, and
  show a diff vs the live zone. **[R] The diff proves *record-set equivalence for
  operator data only*, NOT byte equivalence** — it is computed record-set vs
  record-set with `managed()` (SOA/RRSIG/NSEC\*/DNSKEY/…) excluded on **both**
  sides, because AXFR carries DNSSEC + named's serial that goddns deliberately
  doesn't own. Comments/formatting/`$TTL` scoping are **not** preserved (goddns
  owns the content now). Hard refusals: **refuse to adopt a currently-signed
  zone** (adopting it as "unsigned-owned" would strip its DNSSEC source material
  and, without `dnssec-policy`, take it bogus — defer to Stage 5); **refuse if
  the on-disk file contains `$GENERATE`/`$INCLUDE`** (unrepresentable, §2).
  **[R] Adopt is reversible:** keep the original `file` directive and pre-adopt
  named.conf state; commit the switch only **after** a post-reload SOA+NS verify
  (§3); on any failure, restore the old `file` directive and `rndc reconfig` —
  no point-of-no-return.
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

- **`named-checkzone` (strict flags) is a hard gate** — never publishes a zone
  named would reject; reloads are per-zone — but it is **necessary, not
  sufficient** (§3 Verify adds the semantic apex SOA+NS check).
- **Every change is snapshotted** — a bad edit is one `restore` away.
- **[R] File access — option (b) is the default for any internet-exposed daemon.**
  *Something* writes the owned zone's file on record CRUD. **(a)** daemon writes
  the file directly (write into the zone dir, like `proxy.d/`) — acceptable only
  for a CLI-only / non-exposed deployment. **(b)** the daemon writes the **store
  only**; a small privileged renderer (root, via a local socket/queue) does
  render + checkzone + write + reload. (b) removes the internet-facing surface's
  file descriptor into the zone dir entirely — a daemon compromise is contained
  to store rows the root renderer then re-validates. One extra moving part (a
  socket) against a real blast-radius reduction.
- **[R] Path-traversal hardening (both options):** the zone filename comes
  **solely from the `owned_zones` row**, never from request input; reject a zone
  name with `/` or `..` or with no owned row; render to a temp file in the same
  dir and rename `O_NOFOLLOW`, refusing if the target is a symlink — defeats a
  symlink pivot to `/var/named`/`named.conf`/the binary. `$INCLUDE`/`$GENERATE`
  are **directives, not rdata**, so a `dns.RR` Op can't smuggle them in (an
  `AddRR` of `NS`/`CNAME`/`DNAME` can still break the zone *semantically* —
  caught by §3 Verify, not checkzone).
- **[R] Store-poisoning survives the split — so validate at RENDER time.** The
  daemon and CLI share the store; a compromised daemon with record-CRUD can write
  arbitrary `zone_records`, and a later root `render`/`export`/`rollback` would
  ship that with root's privilege. The renderer therefore **re-runs checkzone +
  semantic verify on every render** (never trusting that store content was
  validated at write time), and the writer-identity column (§1) lets a render
  surface rows the daemon last touched. The split stops the daemon *declaring*
  zones; it does not stop it *poisoning* existing ones — validation must live at
  render, not only at write.

## 7. Interaction with what's already shipped

- **History / snapshots / rollback** — work; for owned zones the snapshot is the
  store's canonical record set (§3), so rollback re-renders byte-exactly. AXFR
  snapshots stay as secondary cross-check history.
- **Record editor (CLI + admin)** — reused via the `filezone` Mutator; owned zones
  gain the same add/del/edit/restore UX as dynamic zones.
- **Zones viewer** — owned zones show as kind `managed`, with edit controls and
  import/export.
- **Dynamic zones, proxy, DDNS tokens, TSIG keyring** — untouched.
- Implements the long-standing `BACKLOG.md` "Phase 4 — Platform: backends" item
  for the self-hosted (non-panel) case.

## 8. Decisions (resolved by the design review) **[R]**

1. **named.conf glue → manual paste is the DEFAULT; the `zones.d/` fragment dir is
   an explicit opt-in.** The fragment dir grants "goddns may make named
   authoritative for arbitrary names" — a strictly larger privilege than goddns
   holds today — and store-poisoning (§6) means the daemon can influence content
   even with lifecycle gated. Convenience isn't worth making that grant the
   default. When opted in, fragment writes stay **root-CLI with operator-typed
   zone names only** (never names sourced from the store/daemon).
2. **Daemon file access → option (b) (store-only daemon + privileged renderer) for
   any internet-exposed deployment;** option (a) (direct file write) only for a
   CLI-only / non-exposed install. Contains a daemon compromise to store rows the
   root renderer re-validates (§6).
3. **Zone dir → `/var/lib/goddns/zones/`** (data goddns owns/rewrites, not config;
   no `/etc` config-management collisions). Hard startup precondition: it must be
   a path **no hand-static zone uses**, so a path collision can't arise (§2).
4. **Serial → date-based `YYYYMMDDnn`, floored on the live serial:**
   `next = max(store, live, todayNN) + 1`, `nn`-overflow → `live + 1` (§3). The
   integrity is the floor, not the format; plain unixtime is the safer-by-
   construction alternative if we'd rather not implement the floor, but date-based
   is fine *with* the floor.
5. **DNSSEC → unsigned-only, confirmed, with a hard refusal gate.** goddns manages
   the unsigned zone and never writes RRSIG/DNSKEY/NSEC\* (the `managed()`
   exclusion); named's `dnssec-policy` / inline-signing signs on top. "Unsigned
   first" is safe for **create**; it is **not** safe for **adopt of an
   already-signed zone** — so adopt/import **refuses a currently-signed zone**
   until Stage 5 (else it silently drops the zone's DNSSEC source and risks
   bogus). The exclusion is the right primitive; the missing piece was the refusal
   gate, now in §5.

## 9. Staged build (independent review per step, as in Phase 2)

- **Stage 0** — store schema (`owned_zones` incl. `file_path` + `serial_floor`;
  `zone_records` incl. writer-identity), the canonical zone **renderer** (new
  code, not `named.Canonical` reuse — with test vectors for SOA/NS/`$TTL`/
  `$ORIGIN`/RFC3597), and the strict `named-checkzone` validator. Pure and
  testable; writes nothing live. **The M1 store-as-authority and M2 serial-floor
  models must be reflected here** — they shape the schema.
- **Stage 1** — the `filezone` Mutator (store → render → checkzone → atomic write
  → `rndc reload` → verify) behind `ddns.Mutator`; route `recordmut` to pick the
  backend by ownership; CLI record CRUD on an owned zone. **[R]** plus a
  `goddns owned-zone verify` tripwire that re-checks store ↔ file ↔ live-serial
  agreement for every owned zone (catches out-of-band edits / the split-brain
  class cheaply).
- **Stage 2** — zone lifecycle: `create` / `delete` + the named.conf fragment glue,
  CLI/root-only; the privilege split enforced.
- **Stage 3** — `adopt` / `import` (zone-file parse → store, diff vs live, the
  migration path) + store-render `export`.
- **Stage 4** — admin UI: owned-zone record CRUD (reuse the record editor),
  import/export buttons; the daemon never crosses into zone lifecycle.
- **Stage 5** — DNSSEC interop (inline-signing), signed owned zones.

Each stage: design-conformant, snapshot-before, `checkzone`-gated, independently
reviewed, squash-merged — same rhythm that carried Phase 2.
