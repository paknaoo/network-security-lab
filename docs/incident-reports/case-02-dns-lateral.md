# Incident Report: DNS Exfiltration Pattern and Intra-Cluster Lateral Movement Attempt

**Report ID:** NSL-IR-2026-002
**Date of incident:** 2026-09-09
**Date of report:** 2026-09-09
**Analyst:** Adam
**Environment:** network-security-lab (k8s-cilium-lab infrastructure)

---

## 1. Executive Summary

On 2026-09-09, two distinct security-relevant activities were observed within the environment: (A) a burst of DNS queries from the management-segment host `192.168.50.99` exhibiting a data-exfiltration/tunneling pattern (20 randomized subdomains under a single suspicious domain within ~5 seconds), and (B) an attempted lateral connection from an unprivileged in-cluster pod (`attacker-pod`) to a restricted internal service, blocked by network policy. These two activities originated from **different sources** (an external VM and an in-cluster pod respectively) and **no telemetry links them causally**; they are analyzed together as representative stages of a post-compromise attack model (exfiltration preparation + lateral movement), not as a confirmed single chain. Neither activity resulted in observed data loss or successful lateral access.

## 2. Incident Classification

| Field | Value |
|---|---|
| **Classification** | True Positive (both activities) |
| **Severity** | Medium (A: DNS pattern) / Low (B: blocked lateral attempt) |
| **Status** | Contained |
| **Affected assets** | A: DNS resolver path via pfSense; B: `phase03-internal-service` (target of blocked attempt) |
| **Sources** | A: `192.168.50.99` (OUTSIDE VM); B: `attacker-pod` in `phase03-lateral-movement` namespace |
| **Attack category** | A: Exfiltration / C2 pattern (DNS tunneling) · B: Lateral movement attempt |

**Correlation caveat (Assessed):** despite both fitting a post-compromise narrative, the two stages share no common source identity, no overlapping 5-tuple, and are separated by ~54 minutes. Treating them as one campaign would exceed what the evidence supports.

## 3. Timeline (facts only)

| Time (UTC) | Source → Destination | Event | Result |
|---|---|---|---|
| `20:27:13.79` – `20:27:19.00` | `192.168.50.99` → DNS (via pfSense) | 20 unique randomized subdomains `<32-hex>.exfil-test.example.com` (`sid:9000005` ×20) | Queries emitted; each a distinct high-entropy label |
| `20:27:18.99` (approx.) | `192.168.50.99` → DNS | Volume threshold crossed (`sid:9000006` ×1) | Alert on ≥15 queries in 5s |
| `21:21:28.630` | `attacker-pod` → `phase03-internal-service:80` | 1st TCP SYN | **FORWARDED** (single packet) |
| `21:21:28.671` – `21:21:32.766` | `attacker-pod` → `phase03-internal-service:80` | 10× TCP SYN (retransmissions) | **DROPPED** — `POLICY_DENIED` |
| `21:21:33.7xx` | `trusted-client` → `phase03-internal-service:80` | Full TCP session (control comparison) | **FORWARDED** — `ingress_allowed_by: phase03-internal-service-restrict-to-trusted` |

## 4. Detection

**Stage A (DNS pattern)** was detected by Suricata on `ens33` via two complementary custom rules: a content-based signature matching the suspicious domain (`sid:9000005`, fired on all 20 queries) and a volume-based signature (`sid:9000006`, fired once when ≥15 queries occurred within 5 seconds). This demonstrates two detection philosophies on the same traffic — signature-based (known-bad domain) and behavioral (query rate independent of content). *Observed.*

Detection note (Assessed): the content rule depends on prior knowledge of the malicious domain. Against a previously-unknown tunneling domain, only the behavioral rule (`9000006`) would have fired — a meaningful distinction for real-world coverage.

**Stage B (lateral movement)** generated **no Suricata alert** — the traffic was pod-to-pod cross-node, encapsulated in VXLAN, and therefore opaque to the LAN tap (consistent with limitations documented in Phase 02). Detection was possible **only via Hubble**, which recorded the policy verdict at the eBPF layer: 10× `DROPPED` with `drop_reason_desc: POLICY_DENIED`, contrasted against the `trusted-client` control which was `FORWARDED` with an explicit `ingress_allowed_by` naming the responsible policy. *Observed (Hubble); not observable via Suricata or pfSense.*

First-packet note (Observed, previously documented): the very first SYN from `attacker-pod` was recorded as `FORWARDED` (`21:21:28.630`) ~40ms before the first `DROPPED` (`21:21:28.671`). This reproduces the behavior documented in Phases 03–04 — the first packet of a new flow may pass before the ingress policy decision is fully applied in connection tracking on the destination node, after which retransmissions are consistently dropped. This is not a policy failure; it is a known datapath timing characteristic.

## 5. Technical Analysis / Attack Path

The two activities map to different points in a post-compromise model:

- **Stage A — Exfiltration/C2 preparation (Observed):** the pattern (many unique high-entropy subdomains under one domain, emitted in rapid succession) is characteristic of DNS tunneling — encoding data into query names sent to an attacker-controlled authoritative server. *What was Observed:* 20 distinct queries, each with a 32-hex-character label, to `exfil-test.example.com`, all traversing the pfSense DNS path. *Not observed / cannot confirm:* whether any data was actually encoded/exfiltrated — the lab domain does not resolve to a real exfiltration endpoint, so no response-side confirmation exists. The **pattern** is confirmed; **actual data loss is not**.

- **Stage B — Lateral movement attempt (Observed):** an unprivileged pod (no `hostNetwork`, no `privileged`, standard Cilium identity) attempted to reach a restricted internal service across namespaces. The CiliumNetworkPolicy `phase03-internal-service-restrict-to-trusted` denied ingress because `attacker-pod` lacks the `role: trusted` label required by the policy. The `trusted-client` control (identical path, only differing by that label) succeeded — confirming the block was identity/label-based, not a general connectivity failure.

## 6. Impact Assessment

| Activity | Attempted | Successful | Evidence |
|---|---|---|---|
| DNS tunneling pattern | Yes (20 queries) | Pattern present; **data loss not confirmed** | Observed (queries) / cannot confirm (exfil) |
| Lateral movement | Yes (11 SYN) | **No** — 10/11 dropped by policy; 1st-packet forwarded but connection never established | Observed |

**No successful lateral access was observed** — the single forwarded SYN did not complete a handshake (no SYN-ACK returned to `attacker-pod`; the connection never reached `established`). **No confirmed data exfiltration** — only the query pattern is Observed; exfiltration success is Not observed.

## 7. Recommendations

1. **Prioritize behavioral DNS detection over domain-list dependence.** The content rule (`9000005`) only works against known domains. Ensure the volume/entropy-based rule (`9000006`) is tuned to catch unknown tunneling domains, and consider adding subdomain-entropy or query-length heuristics.

2. **Investigate DNS egress policy.** The queries reached the pfSense resolver and out to the internet. Consider whether the management segment should be permitted to resolve arbitrary external domains, or restricted to an allowlist — DNS tunneling depends on reaching an attacker-controlled authoritative server.

3. **Confirm Hubble as the authoritative source for east-west policy events.** Stage B was invisible to both Suricata and pfSense. Any detection/response process for intra-cluster lateral movement must treat Hubble (not network taps) as primary.

4. **Consider the first-packet forward window.** While not a policy failure, the ~40ms window where the first SYN is forwarded before enforcement should be understood — for single-packet protocols (UDP-based) it could theoretically permit one packet through. Assess whether this matters for the protected services.

## 8. Evidence

All artifacts in `snapshots/phase-05/`:
- `eve-alerts-session.json` — Suricata DNS alerts (`sid:9000005` ×20, `9000006` ×1)
- `hubble-phase05-relevant-events.json` — Hubble policy verdicts (Stage B: 10 DROPPED, 1 FORWARDED, control comparison)

All timestamps and counts verified programmatically against source artifacts.
