# Phase 4 — in-place zone editing (file-as-truth)

Status: **proposal — file-as-truth model, hardened by an independent design
review (changes marked [R]).** An earlier draft made
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

For a record change (add / delete / change) on an enabled static zone, the whole
read-modify-write runs **inside one `flock(LOCK_EX)` critical section** (M1):

```
1. open the file O_NOFOLLOW; flock(LOCK_EX) the descriptor and HOLD it; read the bytes
2. tokenize it with a line-aware tokenizer (NOT miekg's resolver) → records + an
   exact source-line map; parse with miekg only to VALIDATE well-formedness (M2)
3. apply the Op surgically: rewrite only the target record's source line(s),
   leaving comments / $directives / ordering / whitespace untouched
   (records goddns can't map unambiguously → refuse, fall back to raw mode — §4)
4. bump the SOA serial (read current from the tokenized SOA → max(current+1,
   todayNN); never below current)
5. named-checkzone (strict flags, same BIND as the running server — S5) ← HARD GATE
6. re-read the bytes UNDER THE HELD LOCK and compare to the bytes from step 1;
   if they differ, REFUSE ("changed under you — reload & reapply") ← the nano guard
7. save the raw pre-edit file BYTES as the rollback artifact (separate from the
   Phase-1 canonical AXFR snapshot, which is for diff/history, not file rollback — S5)
8. write the new bytes back under the still-held lock (temp + rename + fsync, in
   the locked dir; refuse a symlink target), then release the lock
9. rndc reload <zone>  (per-zone blast radius; if rndc unreachable → write failed)
10. verify (apex SOA serial bumped + apex NS set matches) + audit
```

Rollback = restore the saved pre-edit **bytes** → checkzone → write → reload, routed
through this same locked pipeline (O3). The same pipeline backs both structured
edits and the raw-text mode (§4); `recordmut`'s preview/diff/confirm/snapshot/audit
machinery is reused, with a new `filezone` apply backend behind the `ddns.Mutator`
seam.

## 3. Coexisting with nano — optimistic concurrency (and its honest limit) [R]

This is the answer to "if I nano it in a hurry, will we kill each other?" — **almost
never, and never silently within goddns's own writers; with `nano` the window is
tiny and detected, not a guarantee.** The mechanism (M1): goddns holds an advisory
`flock(LOCK_EX)` across the entire read-modify-write, and re-reads + byte-compares
the file against what it first read **immediately before writing, under that lock**.
If the bytes changed, it refuses that one write.

**The honest caveat:** `flock` is **advisory** — `nano`/`vim` do not take it. So the
lock *perfectly* serializes goddns-vs-goddns and goddns-vs-(root helper); for
goddns-vs-`nano` the **byte-compare under the lock** is what protects you: a `nano`
save that lands before goddns's pre-write re-read is detected (refused); the only
residual is a `nano` save in the sub-millisecond gap between that re-read and the
rename — narrowed to almost nothing, not zero. The earlier "git non-fast-forward"
framing was too strong: this is a check-and-write under a lock, which bounds the
window to ~one syscall, not a true atomic CAS. The doc states the limit rather than
overselling a guarantee.

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

Views are never refused (they always read fresh). The refusal is a per-write
freshness check (you reload and proceed), never "goddns sulks because you
hand-edited." Because the file is the only truth, there is no second copy to
drift: goddns always edits against what's on disk right now.

## 4. Surgical edits vs raw mode

**[R] miekg `dns.ZoneParser` cannot drive surgical editing.** It emits fully
*resolved* RRs (FQDN owners, inherited TTLs, expanded `@`, applied
`$ORIGIN`/`$TTL`) and discards the surface syntax — there is no parsed-RR →
source-line map, and inverting that resolution is exactly where hand-crafted zones
break (a record with an **omitted owner** inherited from the line above, a TTL from
a `$TTL` 100 lines up, a parenthesised multi-line SOA, mid-file `$ORIGIN`
re-scoping). Nothing in the existing code preserves source formatting
(`named.Canonical` deliberately flattens). So:

- **Structured** edits run on a **custom line-aware tokenizer** that tracks, per
  physical line: implied-owner inheritance, current `$ORIGIN`/`$TTL` scope, paren
  continuation, and trailing comments. It rewrites only the target line(s) and
  leaves everything else byte for byte. **miekg is used only as a validator** —
  parse the candidate to confirm it's well-formed, never to locate edits.
- **Stage 0 handles the safe subset and REFUSES the rest** (→ raw mode, with a
  clear reason): a record is surgically editable only if its source line carries an
  **explicit owner** (and the line below it doesn't depend on owner inheritance),
  is single-line, and sits outside any paren group except the SOA-serial bump.
  Refuse (raw-only): owner-name omission on the target or adjacent record,
  multi-line records, mid-file `$ORIGIN` re-scope, `$INCLUDE` / `$GENERATE`, and
  **in-file DNSSEC records** (`RRSIG`/`DNSKEY`/`NSEC*` — reuse `named.Signed` /
  `recordmut.managed`; an explicitly key-signed file would break on edit).
- **Raw** (power mode, webmin-style): edit the whole file; checkzone gates the save.
  **[R] Raw mode is far more dangerous** (arbitrary whole-file content — a smuggled
  in-bailiwick delegation/glue or wholesale rdata rewrite passes checkzone), so it
  is **CLI-only / off for the daemon by default** (S2); the option-(b) helper
  rejects raw whole-file content (§7).

The line-aware tokenizer + an **adversarial corpus** of hand-zones (implied owners,
comments inside SOA parens, mixed tabs, `$ORIGIN` switches) is the explicit
**Stage 0 deliverable and gate** — building Stage 0 on miekg's resolved records
would corrupt zones.

## 5. Serial — read from the file, bump, never regress

goddns reads the current SOA serial **from the file** (via the §4 tokenizer — for
a parenthesised SOA the serial is one token across lines) and writes
`next = max(current + 1, YYYYMMDD00-for-today)`. Because the file is the only
truth, there is **no floor-vs-store split-brain**: if a hand-edit already bumped
the serial, goddns reads the new value next time. The only rule is "never write a
serial below what the file already has" — satisfied by reading it first.

**[R] One subtlety for provenance (S1):** for an **inline-signed** zone the *file*
serial goddns writes and the *served* serial named publishes differ (named keeps
its own signed serial). The history poller reads the **served** serial (a DNS
query). So goddns records, in its audit line, the **file serial it wrote** — that,
not the served value, is what §6 matches on.

## 6. History — the dual purpose

The Phase-1 history Poller (SOA-poll → on-change AXFR → snapshot, already running
in `serve`) **watches the enabled static zones**. So:

- a **goddns** edit bumps the serial → the poller snapshots it;
- a **nano** edit bumps the serial → the poller snapshots it **too**.

History / diff / rollback then work **uniformly for both**, and you get a change
feed for hand-edits you'd otherwise have no record of. **[R] "Who" is a best-effort
hint, not a guarantee** (S1): a serial move whose value matches a `record-edit`
audit line = goddns; otherwise external (a hand-edit). It can mislabel when a
hand-edit and a goddns edit collapse into one poll cycle, or on inline-signed zones
where the served serial differs (so match on the **file** serial goddns audited,
§5). This is the dual purpose: the same zones are **editable** and **continuously
tracked**, and the lock + the poller reinforce each other (a hand-edit is both
captured *and* makes goddns's next write re-read fresh).

## 7. Safety & risk surface (the dangerous part, honestly)

goddns now **writes static zone files** — the thing to be careful about.

- **`named-checkzone` (strict: `-k fail -m fail -n fail -i full`) is a hard gate**,
  but necessary-not-sufficient: it passes some semantically broken states (dangling
  NS, broken delegation, missing glue). So step 10 adds a **post-reload semantic
  verify** (apex SOA serial + NS set match what was written); on mismatch, restore
  the pre-edit bytes and reload. **[R]** checkzone must be the **same BIND build as
  the running `named`** (S5) — a version/flag skew can pass a zone the live server
  then rejects on reload (caught only by the semantic verify, more expensively).
- **[R] Rollback artifact is the raw pre-edit file BYTES** (step 7), a **separate**
  store from the Phase-1 canonical AXFR snapshot — the latter is sorted/flattened
  canonical text (good for diff/history, wrong for a byte-faithful file restore).
  Recovery restores those bytes verbatim through the locked pipeline (O3).
- **Atomic + path-safe write**: temp + rename + fsync, `O_NOFOLLOW`, refuse a
  symlink target; the filename is taken from the zone's **named.conf-declared
  `file` path**, never from request input; reject any zone not on the allowlist.
  Reloads are per-zone; if `rndc` is unreachable the write is **failed**.
- **[R] Daemon blast radius — the real exposure.** A compromised internet-facing
  daemon controls record rdata and which allowlisted zone to target. Bounds:
  (i) editing limited to the **explicit allowlist** (never panel, never auto-added);
  (ii) **raw whole-file mode is CLI-only** — never on the daemon path (S2), since
  it can rewrite an entire allowlisted zone past checkzone; (iii) for an exposed
  daemon, **option (b)**: the daemon sends only **structured ops** `{zone, op, rr}`
  to a small **root helper** that **re-reads the file and re-derives the edit
  itself** (its own tokenizer + flock + checkzone + write + reload) and
  **re-validates the allowlist** — it **never accepts a full file** from the daemon
  (S3). So the daemon controls only `(zone ∈ allowlist, one op, rdata)`. Daemon
  editing is **off by default** (CLI-only) until enabled.
- **[R] Panel safety — fail CLOSED** (S4): `zone enable` performs a **positive
  not-panel-managed check** at enable time (path not under any known panel tree
  **and** no panel markers in the file) and records the assertion; if panel status
  is **unknown, refuse to enable** (don't allow). Otherwise goddns could surgically
  edit a file a panel re-renders from its DB — goddns's edit vanishes and a serial
  war starts. A `dns.RR` Op can't smuggle `$INCLUDE`/`$GENERATE` (directives, not
  rdata), but an `AddRR` of `NS`/`DNAME`/`CNAME` can still break the zone
  semantically — caught by the §3-step-10 verify, not checkzone.

## 8. Decisions

1. **Editable set** → an **explicit allowlist**, set **only by the root CLI
   `zone enable`** (never a daemon endpoint — O2), with a positive
   not-panel-managed check that **fails closed** on unknown (S4). goddns never
   edits a zone not on it, nor a panel/dynamic zone. The option-(b) helper reads
   the allowlist from a path the daemon cannot write.
2. **Concurrency** → advisory `flock(LOCK_EX)` held across the read-modify-write +
   a **byte-compare under the lock** before writing (M1) — not stat/mtime
   comparison. Stated as a narrowed window vs `nano`, not a guarantee.
3. **Daemon write path** → **option (b)**, **structured ops only** (the helper
   re-derives the edit; never accepts a full file — S3); CLI writes directly;
   **raw whole-file mode is CLI-only** (S2); daemon editing off by default.
4. **Surgical editing** → a **custom line-aware tokenizer** (miekg as validator
   only), restricted to the safe subset; everything else falls back to raw mode
   (M2).
5. **Serial** → read from the file, `next = max(current+1, todayNN)`; provenance
   matched on the **file** serial goddns audited (S1).
6. **DNSSEC** → refuse in-file key-signed zones (detect via `named.Signed` from the
   file records; "is it inline-signed?" is answered from **named.conf**, not the
   unsigned source — O1); inline-signing source edits are safe (named re-signs).
7. **Panel zones** → hard read-only, always.

## 9. What this dissolves from the store-owned draft

Folding to file-as-truth **removes** most of the prior design-review hazards
outright: ownership detection / the `; goddns-owned` marker, the serial floor
vs the store, store-poisoning, and the adopt/import *migration* (there's nothing
to migrate — you just start editing the existing file). The `owned_zones` /
`zone_records` schema is **not needed**; history uses the existing snapshot store.
Import/export reduce to trivialities: **export** = download the file; **import** =
raw-mode replace (checkzone-gated).

## 10. Staged build (independent review per step, as in Phase 2)

- **Stage 0** — **[R] the line-aware tokenizer** (implied-owner / `$ORIGIN`/`$TTL`
  scope / paren continuation / comments) + the surgical insert/replace/remove
  preserving everything else + SOA-serial bump + the strict `named-checkzone`
  wrapper (miekg as validator only). Gated by an **adversarial hand-zone corpus**.
  Pure and testable; writes nothing live. This is the real new code — budget it.
- **Stage 1** — the `filezone` apply path (**flock + byte-compare** → raw-bytes
  snapshot → atomic write → `rndc reload` → semantic verify) behind `ddns.Mutator`;
  the CLI-only allowlist + fail-closed panel/dynamic refusal; CLI record CRUD on an
  enabled static zone.
- **Stage 2** — export (download) + import (CLI raw replace). **Raw whole-file mode
  is CLI-only here** (S2).
- **Stage 3** — admin UI: structured record CRUD only + the optimistic-lock UX
  ("changed under you — reload"); reuse the record-editor components. (Raw mode
  stays CLI.)
- **Stage 4** — wire the history Poller to the enabled static zones (the dual
  purpose), and the option-(b) **structured-ops** root helper for daemon writes.
- **Stage 5** — DNSSEC interaction polish (inline-signing source edits; refuse
  in-file-signed).

Each stage: snapshot-before, checkzone-gated, optimistic-locked, independently
reviewed, squash-merged — the rhythm that carried Phase 2.
