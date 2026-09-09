# Phase 05 — Log Correlation, Manual Timeline Reconstruction

This phase extends the single-event correlation from Phase 04 to a sequence of several independent events spread over time — simulating a full investigation without SIEM support, with a manual reconstruction of the chronology from every available source, and a documented account of the time and effort this process takes.

---

## Goal

Generate a sequence of several distinct events (a mix of Phase 03 scenarios) spread over a longer time window, and manually reconstruct the full timeline from logs without SIEM assistance — while explicitly separating signal from noise, and recording the effort this takes as a reference point for a future discussion of SIEM's value at scale.

---

## What Was Built

- A sequence of five attack events (reusing Phase 03 techniques: port scan, DNS tunneling, HTTP recon, a pfSense block, a CiliumNetworkPolicy block) spread across a roughly 57-minute window (`20:24`–`21:22` UTC), with each step preceded by a `date -u` note as a hard reference point.
- A continuous `hubble observe --follow -o json` capture spanning the entire session window, unlike the short, point-in-time captures used in earlier phases.
- An unplanned, fully real side incident during the session: `phase03-webserver` (the Scenario 2 target) stopped responding to traffic from `attacker`, because the `CiliumNetworkPolicy` deployed for Scenario 5 in Phase 03 covered the same pod as Scenario 2, silently blocking north-south (`reserved:world`) traffic alongside the intended east-west traffic. Diagnosed by systematic elimination (ARP, the pfSense state table, `tcpdump` on the node interface, `cilium-dbg service/endpoint list`, and finally `hubble observe` with `drop_reason_desc:"POLICY_DENIED"`), and fixed architecturally: a new, independent target, `phase03-internal-service`, dedicated solely to Scenario 5, with its own policy, with no effect on Scenario 2.
- Raw logs were collected from all sources for the entire session window: `eve-session-window.json` (3,512 Suricata events), `eve-alerts-session.json` (49 alerts), `pfsense-filterlog-session.txt` (80 block entries), `hubble-phase05-relevant-events.json` (258 Hubble events for the pods under test).

---

## Validation Results

### Reconstructed Timeline

| Time (UTC) | Event | Evidence (exact count) | Classification |
| --- | --- | --- | --- |
| `20:24:41` | Continuous Hubble capture started | — | Reference point |
| `20:25:53`–`20:25:58` | **Event 1 — Port scan** | `sid:2001219`×1 + `sid:9000001`×1 (`→10.10.10.254:80`) | Signal |
| `20:27:13`–`20:27:19` | **Event 2 — DNS tunneling** | `sid:9000005`×20 + `sid:9000006`×1 | Signal |
| `20:29:08`–`21:06:35` | 10× `sid:9000001` on `10.10.10.201:80`, 10 distinct timestamps | Suricata (false threshold match) | **Noise** — policy-incident diagnostics |
| `21:06:07` | `sid:2001219`×1, source `10.20.20.10` (WireGuard) | Suricata | **Noise** — an unrelated `mgmt → worker1` SSH diagnostic session |
| `21:19:20`–`21:19:21` | **Event 3 — HTTP recon** (after the policy fix) | `sid:9000002`×6, `sid:9000003`×2, `sid:9000004`×2, plus ET: `2031502`×2, `2002677`×1, `2049400`×2 | Signal |
| `21:20:23`–`21:20:25` | **Event 4 — SSH attempt, blocked by pfSense** | pfSense `filterlog`×2 entries + Suricata `flow` (`alerted:false`) | Signal |
| `21:21:28`–`21:21:33` | **Event 5 — lateral movement, blocked by CiliumNetworkPolicy** | Hubble: `attacker-pod` → 10× `DROPPED` + 1× `FORWARDED` (first SYN); `trusted-client` → 17× `FORWARDED`, with an explicit `ingress_allowed_by:"phase03-internal-service-restrict-to-trusted"` | Signal |

### Full Alert Breakdown (Programmatically Verified)

All 49 alerts in `eve-alerts-session.json`, counted by `signature_id`:

| `sid` | Count | Attribution |
| --- | --- | --- |
| 2001219 | 2 | 1× Event 1, 1× noise (WireGuard) |
| 2002677 | 1 | Event 3 |
| 2031502 | 2 | Event 3 |
| 2049400 | 2 | Event 3 |
| 9000001 | 11 | 1× Event 1, 10× noise |
| 9000002 | 6 | Event 3 |
| 9000003 | 2 | Event 3 |
| 9000004 | 2 | Event 3 |
| 9000005 | 20 | Event 2 |
| 9000006 | 1 | Event 2 |
| **Total** | **49** | matches `wc -l eve-alerts-session.json` |

**Signal-to-noise balance:** 11 of 49 Suricata alerts (~22%) are noise — 10× `sid:9000001` (retransmitted SYNs generated while diagnosing the policy-conflict incident, not a deliberate attack) plus 1× `sid:2001219` (an unrelated administrative SSH session over WireGuard, incidentally matching an SSH-scan signature). Distinguishing this from Event 1 was possible only via the session's own `date -u` timestamps, not from the alert content itself.

**An additional, initially overlooked source of noise — found in `pfsense-filterlog-session.txt`:** of the 80 block entries in this file, only **2 lines** (`21:20:24`, `21:20:25`) correlate with Event 4. The remaining **78 lines** are outbound traffic from `attacker` to external IP addresses on ports 443 (HTTPS) and 123 (NTP), rejected under the zero-standing-egress policy established in Phase 03 — `attacker`'s own operating system routinely attempting connectivity to external time/update servers, unrelated to any planned scenario. This is a separate category of noise, specific to pfSense, not accounted for in the Suricata-alert balance above — it shows that even a single log source carries multiple, independent layers of noise, not only the kind generated by incident diagnostics.

**Event 5 — a confirmed repeat of the Phase 03/04 pattern:** the same mechanism observed previously — the first SYN of a new flow passing as `FORWARDED` before the policy decision is fully applied in connection tracking, with subsequent retransmissions consistently `DROPPED` — occurred again, independently of the earlier session: 1× `FORWARDED` + 10× `DROPPED` for `attacker-pod`. This is not a new observation but a confirmation that the phenomenon documented in Phase 04 is reproducible.

### Documented Time and Effort of Manual Correlation

- Generating and noting the five attack events: ~15 minutes of active time (spread across the ~57-minute session).
- Diagnosing and fixing the unplanned incident (the policy conflict, initially misattributed to an L2 Announcement infrastructure failure): **~48 minutes**, including checking ARP on three machines, the pfSense state table, `tcpdump` on the cluster node, and ruling out two hypotheses (L2 Announcement, a Cilium agent restart) before finding the actual cause in the Hubble log.
- Manually collecting and filtering logs from four sources into an analysable form: ~20 minutes (creating directories, transferring files, filtering the raw 3,512 lines down to 49 relevant alerts).
- Manually reconstructing and verifying the chronology from four independent log formats (Suricata JSON, pfSense text, Hubble JSON) into a single, consistent table: ~25 minutes.
- **Total: over 100 minutes of analytical work for five planned events within a 57-minute window** — of which nearly half (48 minutes) was spent distinguishing a genuine security concern from an infrastructure fault. This directly illustrates the value of correlation-automating tooling (SIEM) at greater scale — in this session, a single unplanned side incident nearly dominated the entire time budget.

---

## Problems Encountered and Resolutions

- **A conflict between two independent `CiliumNetworkPolicy` resources on one shared pod** (`phase03-webserver`) — the policy deployed for Scenario 5 in Phase 03 was never scoped exclusively to lateral-movement traffic, so it also blocked legitimate north-south traffic for Scenario 2. Resolved by eliminating hypotheses in turn (ARP on Suricata and pfSense — correct; the pfSense state table — the packet was correctly forwarded; `tcpdump` on `k8s-worker1` — the SYN physically arrived; `cilium-dbg service/endpoint list` — the LB and endpoint were correct) until an explicit `drop_reason_desc:"POLICY_DENIED"` was found in the Hubble log. Fixed architecturally: a new, dedicated target, `phase03-internal-service`, with its own, isolated policy.
- **A genuine, concurrent infrastructure incident** (a momentary `kube-apiserver` disruption causing `k8s-worker1` to lose its L2 Announcement lease) occurred independently and in a similar time window, further complicating the diagnosis — restarting the Cilium agent (a reasonable hypothesis at the time) did not resolve the actual problem, because it wasn't the cause. Documented as a deliberate lesson: two independent events overlapping in time require separate, systematic elimination, not an assumption that the first plausible anomaly found is the only cause.
- **The continuous Hubble capture was interrupted** (the `hubble observe --follow` process stopped writing after roughly `21:01`, likely due to a Relay connection drop during the Cilium agent restart) — not noticed immediately, only discovered when attempting to correlate Event 4. This left a gap in Hubble data continuity for part of the session window; it did not affect the final result, since Events 4 and 5 occurred after logging resumed, but it is documented as a limitation of this particular session.
- **Path errors when creating target directories** (`snapshot-phase-05` not created before the first write attempt on `suricata` and `mgmt`) — resolved with a standard `mkdir -p` before every write operation.
- **The first version of this document contained miscounted alert totals** (8 instead of 10, 17 instead of 20, 4 instead of 6, 1 instead of 2, 6 instead of 10, 12 instead of 17) — the result of a manual, surface-level log review rather than a systematic recount. Resolved through a full, programmatic verification of all four evidence files (counting by `signature_id`, and by source/destination/verdict triples) instead of relying on approximate manual counting from the first pass.

---

## Lessons Learned Entries

The following entries were added to [`docs/lessons-learned.md`](lessons-learned.md):

**Topic: Distinguishing signal from noise in logs requires external context, not just alert content — and independent, concurrent infrastructure incidents can mimic or mask security events.**

Previously unclear: whether the mere presence of an alert in a log is enough to classify it as a security event, and whether diagnosing an infrastructure fault and investigating an attack can be treated as independent processes.

What the exercise revealed: 10 of 49 alerts in this session (the custom port-scan threshold rule) were generated not by a deliberate attack but by SYN retransmissions produced while diagnosing an unrelated infrastructure problem — distinguishing this from Event 1 (a genuine port scan) was only possible thanks to external timestamp notes, not by analysing the alert content itself. In addition, a genuine infrastructure fault (a lost L2 Announcement lease) and a genuine configuration error (a conflict between two policies) occurred close together in time, which briefly led to an incorrect causal hypothesis.

Takeaway: threshold rules, without additional operational context, generate false alarms for any repeating network activity, regardless of intent — an analyst has to systematically test and rule out hypotheses one at a time, rather than stopping at the first plausible one, when two independent events overlap in time.

**Topic: Manual log correlation is error-prone at higher data volumes — even with a sound methodology, programmatic verification is necessary, not optional.**

What the exercise additionally revealed: the first version of this very document contained six incorrect counts in its alert table, despite a correct methodology (`grep`, manual review) — the errors came from the act of manually counting many similar, densely packed JSON lines, not from a flawed approach. Only a programmatic recount (`python3` + `Counter`) across all four evidence files revealed the discrepancies.

Takeaway: this is a direct, tangible demonstration of the point raised in Phase 00 about the value of correlation-automating tooling at scale — it applies not only to the volume of logs, but to the reliability of the manual analytical process itself.
