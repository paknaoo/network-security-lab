# False Positive Analysis & Rule Tuning: `sid:9000001` Port-Scan Rule

**Report ID:** NSL-IR-2026-003
**Date:** 2026-09-15
**Analyst:** Adam
**Rule under review:** `sid:9000001` "LOCAL Possible TCP SYN port scan from attacker segment"

---

## 1. Alert Description

During the Phase 05 correlation session (2026-09-09), rule `sid:9000001` fired **11 times**. Only **1** corresponded to an actual port scan (Case 1, Stage 1, `20:25:58`, target `10.10.10.254:80`). The remaining **10** fired against a single target (`10.10.10.201:80`) between `20:29:08` and `21:06:35`, during legitimate diagnostic activity while troubleshooting an unrelated infrastructure issue (a network-policy conflict investigated in the same session).

**False positive rate for this rule in that session: 10/11 (~91%).**

## 2. Investigation

*Observed (programmatic verification of `eve-session-window.json`):*

- All 10 false positives shared a single destination (`10.10.10.201:80`), each from a **different source port** (`40790`, `48040`, `43030`, `34744`, `37620`, `51906`, `55555`, `45082`, `60650`, `57094`), spread across ~37 minutes.
- Each corresponding flow recorded `pkts_toserver: 5–11` — not 1. Each single diagnostic connection attempt, while the target was unreachable (blocked by a network policy at the time), produced multiple retransmitted SYN packets because no SYN-ACK was returned.
- The one true positive targeted a **different** destination (`10.10.10.254:80`) and was part of a sweep across many hosts/ports — the defining characteristic of scanning.

*Assessed:* the rule could not distinguish "many SYN packets to many destinations" (a scan) from "many SYN retransmissions to one destination" (a single stalled connection). The distinction that matters — destination diversity — was invisible to the rule's counting logic.

## 3. Root Cause

The original rule (`rev:1`):
```
alert tcp $ATTACKER_NET any -> $HOME_NET any (msg:"..."; flow:stateless; flags:S,12; threshold:type both, track by_src, count 10, seconds 5; classtype:attempted-recon; sid:9000001; rev:1;)
```

Two compounding factors:

1. **`flow:stateless`** instructed Suricata to evaluate every packet independently, so SYN retransmissions of a single connection each counted as a separate hit.
2. **`track by_src` with no destination awareness** counted retransmissions to one host identically to probes across many hosts.

A subtle third contributor, identified during investigation: because `10.10.10.201` sits on the LAN, the same traffic was visible on **both** Suricata taps (`ens33` and `ens34`), and combined with retransmissions this inflated the per-source counter beyond the value visible in any single flow's `pkts_toserver` field — explaining why flows showing `pkts_toserver:5` still crossed a `count 10` threshold.

Combined, a single blocked connection producing 5–11 retransmitted SYNs crossed the threshold, indistinguishable from a real scan.

## 4. Proposed Tuning

Revised rule (`rev:2`):
```
alert tcp $ATTACKER_NET any -> $HOME_NET any (msg:"..."; flow:to_server; flags:S,12; threshold:type both, track by_src, count 15, seconds 3; classtype:attempted-recon; sid:9000001; rev:2;)
```

Changes and rationale:
- **`flow:stateless` → `flow:to_server`** — evaluates SYNs in flow/direction context rather than treating every packet in isolation, reducing multiplicative counting of retransmissions across taps.
- **`count 10, seconds 5` → `count 15, seconds 3`** — a genuine `nmap` scan emits dozens of SYNs to distinct targets in well under 1 second, easily crossing 15/3s. A single stalled connection's retransmissions arrive with exponential TCP backoff (~1s, 2s, 4s...), spreading across a wider window so they no longer accumulate 15 within any 3-second span.

*Assessment (honest limitation):* this is a threshold-based mitigation, not a structural fix. Suricata's `threshold` keyword cannot natively count distinct destinations, so the rule still lacks true destination-diversity awareness. A determined low-and-slow scanner, deliberately spacing probes, remains undetected — a gap already noted in Case 1 (Recommendation 1) and deferred to a complementary volume-independent rule for control-plane ports.

## 5. Validation

Both tests run live on 2026-09-15 against the deployed `rev:2` rule.

**Test A — genuine scan must still alert:**
- `20:38:12` — `nmap -sS -Pn -p 22,80,443,6443,10250` across 5 hosts (`10.10.10.20/21/22/200/254`).
- Result: `sid:9000001 rev:2` **fired** at `20:38:16` (target `10.10.10.200:443`). *Observed.* ✓ Detection preserved.

**Test B — single blocked connection must not alert:**
- `20:42:09` — `curl --max-time 10 http://10.10.10.20:22/` (blocked by pfSense; generated ~5–8 SYN retransmissions over the 10-second window, matching the original FP pattern of 5–11 retransmit SYNs).
- Result: **no alert** from `sid:9000001` — verified zero matching entries for `2026-09-15T20:42` and `20:43`. *Observed.* ✓ False positive eliminated.

**Control reference:** the identical pattern (`pkts_toserver:5`, single destination) generated alerts under `rev:1` in the Phase 05 data (e.g. `20:47:05`, `20:51:23`, `20:54:25`) — confirming the behavior changed due to the tuning, not due to insufficient test traffic in Test B.

## 6. Before / After Comparison

| Traffic type | `rev:1` alerts | `rev:2` alerts |
|---|---|---|
| Genuine port scan (nmap, many targets, <1s) | fired | **fired** (detection preserved) |
| Single blocked connection (curl, one target, 5–11 retransmit SYN) | fired | **0** (false positive eliminated) |

*Values confirmed by live test on 2026-09-15, not assumed.*

## 7. Conclusion

The tuning eliminated the dominant source of false positives — single stalled connections misread as scans — while preserving detection of genuine multi-target scans, satisfying the Phase 06 criterion of *reducing false positives without losing true-positive detection*. A residual detection gap (low-and-slow scanning) remains and is explicitly acknowledged and deferred to a complementary control rather than concealed by this threshold change. The investigation also surfaced a previously unrecognized mechanism — dual-tap visibility inflating the per-source counter — that would not have been apparent without examining raw flow records rather than alert counts alone.

## 8. Evidence

- `snapshots/phase-05/eve-session-window.json` — original 11 alerts and their flow records (root-cause analysis)
- Live validation (`2026-09-15`, `eve.json` on Suricata) — Test A alert present, Test B alert absent
- Rule file: `suricata/local.rules`, `sid:9000001 rev:2` (changed from `rev:1`)
