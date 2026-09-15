# Phase 06 — Full Incident Investigations (2 cases + false positive)

This phase practises a complete incident-response cycle (identification → analysis → conclusions) on complex, multi-stage cases, ending in formal SOC/IR-style reports, and runs a full tuning cycle on one genuine false positive (root cause → fix → live validation).

---

## Goal

Produce written incident reports resembling real IR documents for two multi-technique cases, and — for a deliberately surfaced false positive — identify the root cause and test a rule change that reduces the false alarm without losing detection of the genuine threat.

---

## What Was Built

**Incident report format (a new artefact type in this repository):** a template close to a real IR document — Executive Summary → Incident Classification → Timeline (facts only) → Detection → Technical Analysis/Attack Path → Impact Assessment → Recommendations → Evidence. For the false-positive analysis, a separate template: Alert Description → Investigation → Root Cause → Proposed Tuning → Validation → Before/After → Conclusion.

**A three-tier confidence discipline** applied consistently across all three documents: **Observed** (directly confirmed by a log/PCAP/alert), **Assessed/Correlated** (a conclusion drawn from several pieces of evidence), and **Not observed / cannot confirm** (what the telemetry does not allow proving). This prevents over-interpretation — for example, an "access attempt" is never described as a "compromise" without evidence.

**Three documents (based on programmatically verified artefacts from Phases 03–05, not reconstruction from memory):**

- **[Case 1 (NSL-IR-2026-001)](incident-reports/case-01-multistage-recon.md) — Multi-stage recon and access attempt:** reconnaissance (port scan) → HTTP recon against `10.10.10.201` (Nikto UA, `/.env`, `/admin`, path traversal) → an SSH attempt against the control plane, blocked by pfSense. All three stages from a single source (`192.168.50.99`) — a coherent chain.
- **[Case 2 (NSL-IR-2026-002)](incident-reports/case-02-dns-lateral.md) — DNS exfiltration pattern + lateral movement:** a DNS-tunneling pattern (20 randomized subdomains) and an in-cluster lateral-movement attempt (`attacker-pod` → `phase03-internal-service`, blocked by CiliumNetworkPolicy, contrasted against `trusted-client`). The lack of a confirmed causal link between the two stages (different sources, ~54 minutes apart) is documented explicitly — analysed as representative stages of an attack model, not as one campaign.
- **[Case 3 (NSL-IR-2026-003)](incident-reports/case-03-false-positive-tuning.md) — False positive analysis & tuning of `sid:9000001`:** a full tuning cycle on a genuine false positive that arose during lab work.

---

## Validation Results

**"A written IR report per case" criterion — met** for both incidents (Case 1, Case 2), with an explicit attempted-vs-successful distinction in every Impact section:

- Case 1: no stage ended in a confirmed compromise (recon dropped by pfSense, HTTP recon reached the service but returned 404/400 with no sensitive data, SSH blocked before reaching the host).
- Case 2: no confirmed exfiltration (only the query pattern is Observed, not the data loss itself), no successful lateral movement (a single first SYN forwarded, but the connection never reached `established`).

**"False positive: root cause + a tested change reducing FP without losing TP" criterion — met and validated live:**

Root cause (Observed, programmatically verified): rule `sid:9000001 rev:1` with `flow:stateless` counted every SYN retransmission independently, and `track by_src` with no destination-diversity awareness could not distinguish "many SYNs to many targets" (a scan) from "many retransmissions to one target" (a single blocked connection). A single blocked `curl` (5–11 SYN retransmissions) crossed the `count 10` threshold.

Fix (`rev:2`): `flow:stateless` → `flow:to_server`, `count 10, seconds 5` → `count 15, seconds 3`.

Live validation (2026-09-15):

- **Test A** (genuine nmap, multiple targets): `sid:9000001 rev:2` **alerted** (`20:38:16`) — detection preserved.
- **Test B** (blocked `curl` to `10.10.10.20:22`, 5–8 SYN retransmissions to one target): **zero alerts** (`20:42`/`20:43`) — false positive eliminated.
- Control reference: the identical pattern (`pkts_toserver:5`, one target) alerted under `rev:1` in the Phase 05 data — confirming the change stems from the tuning, not from insufficient test traffic.

Before/After: genuine scan (fired → fired, preserved), blocked connection (fired → 0, eliminated) — values confirmed by test, not assumed.

---

## Problems Encountered and Resolutions

- **An apparent arithmetic contradiction in the root cause** — the original alerts showed `pkts_toserver:5` against a `count 10` threshold, which initially looked impossible (5 < 10). Resolved by analysing raw events: `flow:stateless`, combined with the same LAN traffic being visible on **both** taps (`ens33` and `ens34`) plus retransmissions, effectively multiplied the `by_src` counter beyond the value visible in any single `pkts_toserver` field. A previously unrecognised mechanism, documented in the report.
- **Risk of an unfaithful FP test** — the first Test B (`nc -w3`) likely sent too few packets (2–3 SYNs) to reproduce the original 5–11 SYN pattern; a lack of alert could then have been due to too little traffic rather than the fix. Resolved with a second Test B (`curl --max-time 10`), which generated 5–8 retransmissions matching the original, plus a control reference to the Phase 05 data confirming that this pattern alerted under the old rule.
- **The threshold could not be derived from data alone** — `eve-session-window.json` did not contain a clean packet count of a genuine scan within a 5-second window, so the threshold was chosen hypothetically and **verified empirically on the live system** rather than derived from incomplete data — consistent with the "tested change" criterion.
- **A deliberate decision on two, not three, attack scenarios** — as agreed, two thoroughly conducted multi-stage investigations plus one genuine FP were judged stronger than three similar cases "for completeness".

---

## Lessons Learned Entry

The following entry was added to [`docs/lessons-learned.md`](lessons-learned.md):

**Topic: Threshold rules without destination-diversity awareness confuse one connection's retransmissions with a scan — and correct tuning requires distinguishing traffic structure, not just adjusting the count.**

Previously unclear: why a rule intended to detect a port scan generated false positives on single, legitimate connections, and whether simply raising the threshold would suffice.

What the exercise revealed: the cause was not too low a threshold value, but the counting logic itself — `flow:stateless` counted a single stalled connection's SYN retransmissions as separate hits, and `track by_src` did not distinguish many targets (a scan) from one target many times (retransmissions). A genuine scan and a blocked connection looked identical to a rule that only looked at the packet count from a single source. The fix (flow context + a narrower window) eliminated the dominant source of FPs, but did not add structural destination-diversity awareness — the remaining gap (a low-and-slow scan) was named explicitly and deferred to a separate, complementary rule rather than hidden.

Takeaway: a threshold rule's false alarm is most often a problem of matching logic (what is counted, and in what context), not of the threshold value itself — and honest tuning names the remaining gaps rather than pretending one change solves everything.
