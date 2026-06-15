# Phase 4 — in-place zone editing (file-as-truth)

Status: **proposal (model revised after operator review).** An earlier draft made
goddns the *sole authority* for a zone with a SQLite canonical store and forbade
hand-editing. That reintroduces the exact collision the original invariant exists
to prevent: **two sources of truth (store ↔ file) that diverge the moment an
operator `nano`s the zone** — and operators do nano zones, by habit, in a hurry.
Rejected. This design makes **the zone file the single source of truth**. goddns
is a validating, history-keeping editor that works **in place** and **alongside**
hand-editing — never a replacement authority. No second copy of the truth → no
split-brain. Phases 1–2 shipped (history/diff; record CRUD on dynamic zones,
snapshot rollback, TSIG rotation, proxy-vhost CRUD); this is the static-zone
editing layer.

## 0. Principles (carried + the new one)

1. Read-only is the default; every write is deliberate, audited, **reversible**.
2. **The file is the single source of truth.** goddns keeps no canonical copy; it
   reads the file fresh, edits it, and writes it back. A hand-edit and a goddns
   edit are the same kind of event to the system.
3. **It coexists with nano** via optimistic concurrency (§3), so the two writers
   can never silently clobber each other.
4. Phase-1 history is the undo, and now also the **change feed** for hand-edits
   (§6) — the "dual purpose".

## 1. Scope & the (revised) invariant

- **Editable**: plain **static master** zones the operator **explicitly enables**
  for goddns editing (an allowlist — goddns never auto-enables a zone), whose file
  goddns has write access to.
- **Never touched**: **panel-managed** zones (cPanel / DirectAdmin / Virtualmin —
  detected, read-only), **dynamic** zones (the RFC2136 path — different
  mechanism), slaves, and **named.conf** itself.
- **Invariant**: *the zone file is the single source of truth; goddns edits it in
  place — surgically, validated with `named-checkzone`, atomically, with
  optimistic concurrency — so it coexists with hand-editing. It keeps no second
  copy of the truth, never writes a panel zone, and never writes named.conf.*

The original "never write a hand-edited static zone" rule was a *means* to an end
(no clobber, no split-brain, respect the operator). File-as-truth + surgical edits
+ optimistic locking + checkzone serve that end **better** than store-as-truth for
an operator who hand-edits — so the means is updated, the end is unchanged.

## 2. The edit pipeline

For a record change (add / delete / change) on an enabled static zone:

```
1. read the file fresh; capture its (mtime, sha256) = the version you're editing
2. parse it (miekg dns.ZoneParser) into records + keep the raw text & line map
3. apply the Op surgically: insert/replace/remove the exact record line(s),
   leaving comments / $directives / ordering / whitespace untouched
4. bump the SOA serial (read current → max(current+1, todayNN); never below current)
5. named-checkzone (strict flags) on the candidate  ← HARD GATE
6. optimistic-lock re-check: re-stat the file; if (mtime, sha256) changed since
   step 1, REFUSE ("changed under you — reload & reapply")  ← the nano-safety
7. snapshot the current (pre-edit) file content (Phase-1 history)
8. atomic write: temp + rename + fsync, O_NOFOLLOW, refuse if target is a symlink
9. rndc reload <zone>  (per-zone blast radius)
10. verify (apex SOA serial bumped + apex NS set matches) + audit
```

Rollback = restore a snapshot's content → checkzone → write → reload. The same
pipeline backs both structured edits and the raw-text mode (§4); `recordmut`'s
preview/diff/confirm/snapshot/audit machinery is reused, with a new `filezone`
apply backend behind the existing `ddns.Mutator` seam.

## 3. Coexisting with nano — optimistic concurrency (the headline guarantee)

This is the answer to "if I nano it in a hurry, will we kill each other?" — **no.**
Step 1 captures the file's `(mtime, sha256)`; step 6 re-checks it just before
writing. If you (or another admin session) changed the file in between, goddns
**refuses that one write** and tells you to reload — it never writes over a change
it didn't see.

It is **stateless and per-write**, not a lock on the zone. A hand-edit does **not**
disable goddns, block future edits, or refuse views. Two cases make this concrete:

- **goddns wasn't editing** (it was closed / down / you had no access, and you just
  `nano`'d a CNAME): nothing to conflict with. Next time you open the zone, goddns
  reads the file fresh — your CNAME is simply the current state — and everything
  works normally. The history poller (§6) already snapshotted your hand-edit.
- **a genuine concurrent edit** (you had a goddns edit form open against the
  pre-`nano` file, then `nano`'d, then hit save): goddns refuses **that save**
  (applying it would silently drop your CNAME), you reload to pick up the current
  file, redo the change, save. Your `nano` edit is never lost — it's on disk the
  whole time; the refusal only stops a stale write from clobbering it.

Views are never refused (they always read fresh). The check is exactly a
compare-and-swap on "did the file move under me for *this* write" — like `git`'s
non-fast-forward push refusal (you `pull`/reload and proceed), not "git refuses to
work because you committed." Because the file is the only truth, there is no second
copy to drift: goddns always edits against what's on disk right now. No lost edits,
no silent clobber.

## 4. Surgical edits vs raw mode

- **Structured** (the default): add/del/change one record → goddns computes the
  **minimal text change** to the relevant line(s) and leaves everything else byte
  for byte — your comments, `$TTL`/`$ORIGIN`, ordering, and spacing survive. This
  is the key difference from a full canonical re-render (which would flatten your
  hand-crafted file).
- **Raw** (power mode, webmin-style): edit the whole file in a textarea; checkzone
  gates the save. You own the consequences; the optimistic lock + snapshot still
  protect you.
- **Refuse** surgical editing of a file containing `$INCLUDE` / `$GENERATE` (the
  line-mapper can't safely reason about generated/incremented content) or **in-file
  DNSSEC records** (an explicitly key-signed zone — editing the signed file breaks
  signatures). Those fall back to raw mode or are refused with a clear reason.

## 5. Serial — read from the file, bump, never regress

goddns reads the current SOA serial **from the file** (truth) and writes
`next = max(current + 1, YYYYMMDD00-for-today)`. Because the file is the only
truth, there is **no floor-vs-store split-brain**: if a hand-edit already bumped
the serial, goddns simply reads the new value next time. The only rule is "never
write a serial below what the file already has" — trivially satisfied by reading
it first.

## 6. History — the dual purpose

The Phase-1 history Poller (SOA-poll → on-change AXFR → snapshot, already running
in `serve`) **watches the enabled static zones**. So:

- a **goddns** edit bumps the serial → the poller snapshots it;
- a **nano** edit bumps the serial → the poller snapshots it **too**.

History / diff / rollback then work **uniformly for both**, and you get a change
feed for hand-edits you'd otherwise have no record of. "Who" is inferred: a serial
move with a matching `admin-audit` line = goddns; a serial move without one =
external (a hand-edit). This is the dual purpose: the same zones are **editable**
and **continuously tracked**, and the optimistic lock + the poller reinforce each
other (a hand-edit is both captured *and* makes goddns's next write re-read fresh).

## 7. Safety & risk surface (the dangerous part, honestly)

goddns now **writes static zone files** — the thing to be careful about.

- **`named-checkzone` (strict: `-k fail -m fail -n fail -i full`) is a hard gate**,
  but necessary-not-sufficient: it passes some semantically broken states (dangling
  NS, broken delegation, missing glue). So step 10 adds a **post-reload semantic
  verify** (apex SOA serial + NS set match what was written); on mismatch, restore
  the pre-edit snapshot and reload.
- **Atomic + path-safe write**: temp + rename + fsync, `O_NOFOLLOW`, refuse a
  symlink target; the filename is taken from the zone's **named.conf-declared
  `file` path**, never from request input; reject any zone not on the editable
  allowlist. Defeats a symlink/path pivot to another file.
- **Pre-edit snapshot = backup**: even a bad surgical edit is one `restore` away;
  reloads are per-zone (blast radius = one zone). If `rndc` is unreachable, the
  write is treated as failed.
- **Daemon blast radius**: the internet-facing daemon (admin UI) writing
  `/var/named`-class files is the real exposure. Bound it: (i) editing is limited
  to the operator's **explicit allowlist** of static zones (never panel, never
  auto-added); (ii) for an exposed daemon, prefer **option (b)** — the daemon
  proposes the edit, a small **root helper** validates (checkzone) + writes +
  reloads, so the daemon never holds a file descriptor into the zone dir; the CLI
  (root) writes directly. Daemon editing can also be left **off by default**
  (CLI-only) for the most conservative posture.
- **Panel safety**: panel-managed zones are detected (file path under a panel's
  tree / known markers) and are **hard read-only**; the allowlist is the primary
  guard (the operator can't enable a panel zone), panel-detection the secondary.
- **Parse fidelity**: the surgical line-mapper must handle multi-line records
  (parenthesised SOA), `$TTL`/`$ORIGIN` scoping, mixed tabs/spaces, and trailing
  comments — covered by test vectors before any live write.

## 8. Decisions

1. **Editable set** → an **explicit allowlist** (config or a CLI `zone enable`);
   goddns never edits a zone the operator didn't opt in, and never a panel/dynamic
   zone.
2. **Daemon write path** → **option (b)** (daemon proposes, root helper writes) for
   any internet-exposed deployment; CLI writes directly; daemon editing off by
   default until enabled.
3. **Serial** → read from the file, `next = max(current+1, todayNN)`.
4. **DNSSEC** → refuse in-file key-signed zones; a zone signed by named's
   inline-signing has an **unsigned source** that is safe to edit (named re-signs
   on reload). Same `managed()` exclusion primitive as `record restore`.
5. **Panel zones** → hard read-only, always.

## 9. What this dissolves from the store-owned draft

Folding to file-as-truth **removes** most of the prior design-review hazards
outright: ownership detection / the `; goddns-owned` marker, the serial floor
vs the store, store-poisoning, and the adopt/import *migration* (there's nothing
to migrate — you just start editing the existing file). The `owned_zones` /
`zone_records` schema is **not needed**; history uses the existing snapshot store.
Import/export reduce to trivialities: **export** = download the file; **import** =
raw-mode replace (checkzone-gated).

## 10. Staged build (independent review per step, as in Phase 2)

- **Stage 0** — the zone-file **surgical-edit engine**: parse (miekg) + line-map +
  insert/replace/remove a record preserving everything else, SOA serial bump, and
  the strict `named-checkzone` wrapper. Pure and testable; writes nothing live.
  (This is the real new code — budget it.)
- **Stage 1** — the `filezone` apply path (optimistic-lock → snapshot → atomic
  write → `rndc reload` → semantic verify) behind `ddns.Mutator`; the editable-zone
  allowlist + panel/dynamic refusal; CLI record CRUD on an enabled static zone.
- **Stage 2** — raw-text mode (whole-file edit, checkzone-gated) + export
  (download) + import (raw replace).
- **Stage 3** — admin UI: structured record CRUD + the raw editor + the
  optimistic-lock UX ("changed under you — reload"); reuse the record-editor
  components.
- **Stage 4** — wire the history Poller to the enabled static zones (the dual
  purpose), and the option-(b) root helper for daemon writes.
- **Stage 5** — DNSSEC interaction polish (inline-signing source edits; refuse
  in-file-signed).

Each stage: snapshot-before, checkzone-gated, optimistic-locked, independently
reviewed, squash-merged — the rhythm that carried Phase 2.
