# Phase 07 — IDS → IPS Transition with Rule Tuning

This phase deliberately and controllably switches Suricata from detection mode to inline blocking (IPS), with a justified split between rules that qualify for automatic blocking (`drop`) and those that remain in observation mode (`alert`).

---

## Goal

Switch Suricata from pure detection to inline blocking in a controlled way, confirm that traffic is actually blocked (not merely alerted), verify that legitimate reference traffic still passes, and document the criteria for which rules qualify for `drop` versus `alert`.

---

## Architectural Decision

Three IPS implementation models were considered: (A) a transparent bridge with transit traffic passing through Suricata, (B) NFQUEUE on Suricata itself, (C) IPS on pfSense via its built-in package. The choice was **an isolated IPS path on Suricata itself via NFQUEUE** — a deliberately narrower scope than the original Phase 00 plan (which assumed inline operation for transit traffic).

Rationale (two priorities): (1) learn the IPS/inline/drop mechanism on Suricata itself, not on pfSense; (2) don't disturb the working topology from Phases 01–06. A transparent bridge (A) would require re-architecting the segments and risked destabilising the environment; IPS on pfSense (C) would mean a second engine instead of Suricata itself. The chosen path satisfies both priorities at the cost of an explicitly documented limitation: Suricata blocks traffic **directed at itself** (test port 9999), not transit `attacker → LAN` traffic. The IPS mechanism (drop/accept) is identical — what's under test is the inline engine itself, not its placement on the production path.

---

## What Was Built

- **A separate IPS config** (`/etc/suricata/suricata-ips.yaml`, a copy of the main one) loading only a dedicated test rules file — without touching the running `suricata.service` from Phases 01–06.
- **Two test rules** (`/var/lib/suricata/rules/rules-ips.rules`), demonstrating the drop-vs-alert split:
  - `sid:9100001` (**drop**): blocks traffic to port 9999 containing the string `"ATTACK"` — representing a low-false-positive-risk rule that qualifies for auto-blocking.
  - `sid:9100002` (**alert**): reports any traffic to port 9999 without blocking — representing a rule deliberately left in observation mode.
- **Suricata run in NFQUEUE mode** (`-q 0 --runmode=workers`), reading packets from the netfilter queue.
- **A narrow iptables rule** (`-A INPUT -p tcp --dport 9999 -j NFQUEUE --queue-num 0 --queue-bypass`) directing **only** port 9999 to the queue — with `--queue-bypass` as a fail-open safeguard and SSH (port 22) explicitly left untouched.

---

## Validation Results

All criteria from [Phase 00](phase-00-planning.md#phase-07--ids--ips-transition-with-rule-tuning) were met:

- **Suricata operates inline** — confirmed by `Engine started` in `-q 0` mode and by the iptables counter (packets actually traversed NFQUEUE rather than bypassing the engine).
- **Traffic actually blocked, not merely alerted** — for a payload containing "ATTACK": a series of `[Drop]` entries (`sid:9100001`) in `fast.log`, ~16 seconds of TCP retransmissions (the client received no ACK because the data was being dropped), and the payload never reached the listener. *This is a qualitative difference from every previous phase — the first time Suricata blocked something rather than only observing it.*
- **Drop-vs-alert split verified in a single time window** — in the `20:44:42` test, two connections to the same port, distinguished solely by content: source port `47666` (payload "ATTACK") → `[Drop]`; source port `47682` (payload "benign") → `alert` only, zero `[Drop]`, passed through.
- **Legitimate-traffic regression checked** — benign traffic was never dropped (zero `[Drop]` for traffic without "ATTACK").
- **Aggregate numeric evidence from the engine** (final NFQUEUE statistics at shutdown): `Treated: Pkts 72` → `Verdict: Accepted 20, Dropped 52, Replaced 0` — 72 engine decisions, 52 packets blocked (attack retransmissions), 20 passed (benign + handshakes).
- **Isolation confirmed** — the main `suricata.service` (IDS, Phases 01–06) stayed `active (running)` throughout the test and after cleanup; SSH (`SSH-OK`) worked uninterrupted thanks to the narrow iptables rule.

Evidence under `snapshots/phase-07/`: `ips-fast-log.txt`, `ips-verdict-stats.txt`, `rules-ips.rules`.

---

## Problems Encountered and Resolutions

- **Wrong rules-file path** — Suricata looked for rules in `default-rule-path` (`/var/lib/suricata/rules/`), while the file was created in `/etc/suricata/`. Caught by `suricata -T` validation (`No rule files match the pattern`). Resolved by moving the file to the correct directory.
- **Unreliable listener-side observation** — `nc -l -k` (with output redirection and as a background job) did not display/record the passed-through benign traffic, which initially looked like an IPS problem. Diagnosed as a buffering/process-management artefact of `nc`, not an engine fault. Resolved by basing the evidence on Suricata's own engine logs (`fast.log` + NFQUEUE verdict statistics), which are conclusive and independent of listener behaviour — benign traffic had zero `[Drop]` entries, confirming it was passed through.
- **Risk of losing SSH access with an inline configuration** — addressed preventively: a narrow iptables rule on port 9999 only (never 22), the `--queue-bypass` fail-open flag, confirmation of `SSH-OK` from a fresh session before generating attack traffic, and confirmed VMware console access as a fallback plan.

---

## Lessons Learned Entry

The following entry was added to [`docs/lessons-learned.md`](lessons-learned.md):

**Topic: Inline/IPS mode is a fundamentally different position in the network than a passive IDS — blocking requires traffic to physically pass through the engine, which is an architectural decision with real consequences for stability.**

Previously unclear: whether moving from IDS to IPS is a configuration change (a flag/mode) or an architectural change.

What the exercise revealed: for six phases Suricata was a passive observer on two taps — traffic didn't pass through it, only a copy, so it couldn't block anything. IPS requires packets to actually **pass through** the engine (here: through the NFQUEUE queue), which places the engine on the traffic path and makes it a potential point of failure. Implementing inline operation for transit traffic would require re-architecting the topology; a narrower, isolated path (traffic directed at Suricata itself) was deliberately chosen, demonstrating the identical drop/accept mechanism without risk to the working environment. Splitting rules into `drop` (low false-positive, auto-block) and `alert` (observation) is not a syntax detail but an operational decision about what is allowed to automatically interfere with traffic.

Takeaway: an IDS observes a copy of traffic and can be wrong without consequences for connectivity; an IPS sits on the traffic path, and any error it makes (a false positive in `drop` mode) genuinely blocks legitimate traffic — which is why only rules with a proven, low false-positive risk qualify for `drop` mode, and the rest stay in `alert`.
