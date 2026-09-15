# Incident Report: Multi-Stage Reconnaissance and Access Attempt from Management Segment

**Report ID:** NSL-IR-2026-001
**Date of incident:** 2026-09-09
**Date of report:** 2026-09-09
**Analyst:** Adam
**Environment:** network-security-lab (k8s-cilium-lab infrastructure)

---

## 1. Executive Summary

Between 20:25 and 21:20 UTC on 2026-09-09, a host on the OUTSIDE management segment (`192.168.50.99`) conducted a multi-stage activity sequence against the protected Kubernetes LAN (`10.10.10.0/24`). The sequence progressed from network reconnaissance (port scanning), through web application probing against an exposed service, to an attempted administrative connection to the Kubernetes control plane. The reconnaissance and web-probing stages reached their targets; the administrative access attempt was blocked at the perimeter firewall. No evidence of successful compromise was observed at any stage. All activity originated from a single internal source and is assessed as a coordinated reconnaissance-and-access attempt rather than isolated events.

## 2. Incident Classification

| Field | Value |
|---|---|
| **Classification** | True Positive |
| **Severity** | Medium |
| **Status** | Contained |
| **Affected assets** | `phase03-webserver` (LoadBalancer VIP `10.10.10.201`); attempted: `k8s-master` (`10.10.10.20:22`), pfSense (`10.10.10.254:80`) |
| **Source** | `192.168.50.99` (OUTSIDE / management segment) |
| **Attack category** | Reconnaissance → Web application probing → Attempted lateral/administrative access |

**Severity rationale (Assessed):** Medium rather than High because although the activity was clearly hostile and reached internal assets, no data exfiltration, no successful authentication, and no policy bypass were observed. The most sensitive target (control-plane SSH) was blocked before reaching the host.

## 3. Timeline (facts only)

All timestamps UTC. Interpretation deferred to Section 5.

| Time | Source → Destination | Event | Result |
|---|---|---|---|
| `20:25:58.740799` | `192.168.50.99` → `10.10.10.20:22` | TCP SYN, detected as SSH scan (`sid:2001219`) | No response observed (`pkts_toclient:0`) |
| `20:25:58.740950` | `192.168.50.99` → `10.10.10.254:80` | TCP SYN port-scan threshold reached (`sid:9000001`) | No response observed |
| `21:19:21.051` | `192.168.50.99` → `10.10.10.201:80` | HTTP GET `/`, User-Agent `Nikto/2.5.0` (`sid:9000002`) | HTTP 200 |
| `21:19:21.068` | `192.168.50.99` → `10.10.10.201:80` | HTTP GET `/.env` (`sid:9000002`, `9000003`, `2031502`) | HTTP 404 |
| `21:19:21.079` | `192.168.50.99` → `10.10.10.201:80` | HTTP GET `/admin` (`sid:9000002`, `2002677`) | HTTP 404 |
| `21:19:21.091` | `192.168.50.99` → `10.10.10.201:80` | HTTP GET `/../../../etc/passwd` (`sid:9000004`, `2049400`) | HTTP 400 |
| `21:20:23.692` – `21:20:24.707` | `192.168.50.99` → `10.10.10.20:22` | 2× TCP SYN to control-plane SSH | Blocked by pfSense (`filterlog`, 21:20:24 & 21:20:25); no response |

## 4. Detection

Detection coverage varied by stage — an important characteristic of this environment's layered visibility.

**Stage 1 (Reconnaissance)** was detected by Suricata on the OUTSIDE tap (`ens33`, pre-filter), via both a custom rule (`sid:9000001`, threshold-based) and an ET Open signature (`sid:2001219`). *Observed.*

Note (Assessed): the scan targeted multiple hosts and ports, but only two alerts fired — one per signature — because the custom threshold rule (`9000001`) requires 10+ SYN packets within 5 seconds from one source before alerting, and a single sweep across five hosts × five ports does not cross that threshold on every host/port combination simultaneously. This is a known property of volume-based detection, revisited in Case 3.

**Stage 2 (Web probing)** was detected by both custom rules and ET Open on `ens33`. Custom rules `9000002` (Nikto User-Agent), `9000003` (`/.env` access), and `9000004` (path traversal, using `http.uri.raw` to bypass URI normalization) fired alongside ET signatures `2031502`, `2002677`, and `2049400`. *Observed.*

**Stage 3 (Administrative access attempt)** generated **no Suricata alert**. Suricata recorded the connection attempt only as a `flow` event (`alerted:false`) with `pkts_toserver:2, pkts_toclient:0`. Detection of the block relied entirely on the pfSense `filterlog`, which recorded two `block` entries against the default-deny rule. Correlation between the Suricata `flow` and the pfSense block was possible via matching 5-tuple (`192.168.50.99:45080 → 10.10.10.20:22`) and timestamp (to the second). *Observed (pfSense); correlated (Suricata↔pfSense).*

Detection-gap note (Assessed): the same source/target pair (`192.168.50.99 → 10.10.10.20:22`) appeared in **both** Stage 1 and Stage 3 with identical technique (SYN, no response), yet Stage 1 alerted and Stage 3 did not — Stage 1 was part of a high-volume burst crossing the detection threshold, while Stage 3 was a single isolated attempt below it. A low-and-slow attacker deliberately spacing attempts would evade the volume-based rule entirely.

## 5. Technical Analysis / Attack Path

The observed sequence maps to a recognizable progression:

**Reconnaissance → Service Discovery → Web Exploitation Attempt → Administrative Access Attempt → Blocked**

- **Reconnaissance (Observed):** the source performed a SYN-based port scan across the LAN, probing SSH, HTTP/HTTPS, Kubernetes API, and kubelet ports. All probes were dropped by pfSense (targets returned no response), but the OUTSIDE tap observed the attempts regardless — consistent with the design intent of pre-filter IDS placement.

- **Web probing (Observed):** ~54 minutes later, the source directed HTTP requests at the one deliberately exposed service (`10.10.10.201:80`). Request contents show classic automated-scanner behavior: a Nikto User-Agent, probes for a sensitive configuration file (`/.env`), a common admin path (`/admin`), and a path-traversal attempt targeting `/etc/passwd`. Server responses (Observed): `/` → 200, `/.env` → 404, `/admin` → 404, `/etc/passwd` → 400. *No sensitive content was returned* — the 404/400 responses indicate the probed resources did not exist or were rejected.

- **Administrative access attempt (Observed):** the source attempted a direct SSH connection to the Kubernetes control plane (`10.10.10.20:22`). pfSense blocked both SYN packets under the default-deny rule; the host never received the traffic.

**Assessment of intent (Assessed, not Observed):** the progression — broad recon, then focused probing of the reachable service, then a targeted attempt at the highest-value administrative endpoint — is consistent with a single actor performing structured attack-path enumeration. However, the ~54-minute and ~1-minute gaps between stages, and the mix of tools (Nikto-style UA, then curl), mean this could also be separate manual actions rather than an automated chain. The telemetry does not allow distinguishing these; both are consistent with the evidence.

## 6. Impact Assessment

| Stage | Attempted | Successful | Evidence |
|---|---|---|---|
| Reconnaissance | Yes | No response from targets (pfSense dropped) | Observed |
| Web probing | Yes | Reached service; no sensitive data returned (404/400) | Observed |
| Admin access (SSH) | Yes | **No** — blocked at perimeter, host never reached | Observed |

**No successful compromise was observed at any stage.** The web service was reached but returned no sensitive content. The administrative access attempt was blocked before reaching the target. There is **no evidence** (Not observed / cannot confirm) of successful authentication, data exfiltration, code execution, or persistence.

## 7. Recommendations

1. **Address the volume-based detection gap (High priority).** The port-scan rule (`sid:9000001`) missed the isolated Stage 3 attempt. Consider supplementing threshold-based detection with a rule that flags *any* connection attempt from the OUTSIDE segment to control-plane ports (`22`, `6443`, `10250`), regardless of volume — the management segment should have a well-defined, small set of legitimate destinations, making low-volume anomalies meaningful.

2. **Improve east-west/administrative visibility.** Stage 3 was invisible to Suricata as an alert and relied solely on pfSense logs. Formalize automated correlation between pfSense `filterlog` and Suricata `flow` records for blocked administrative-port attempts.

3. **Review exposure of `10.10.10.201`.** The service was reachable from the management segment and responded to unauthenticated probing. Confirm this exposure is intentional and consider whether requests bearing known-scanner User-Agents (Nikto, etc.) should be blocked inline (relevant to Phase 07 IDS→IPS work).

4. **Investigate the source host.** `192.168.50.99` on the management segment generated hostile traffic. Per the environment's threat model this represents a compromised or unauthorized host on the administrative network; its presence and legitimacy should be reviewed.

## 8. Evidence

All artifacts in `snapshots/phase-05/`:
- `eve-alerts-session.json` — Suricata alerts (Stages 1, 2)
- `eve-session-window.json` — Suricata `flow` records (Stage 3, `alerted:false`)
- `pfsense-filterlog-session.txt` — pfSense block entries (Stage 3)

All timestamps and counts in this report were verified programmatically against the source artifacts.
