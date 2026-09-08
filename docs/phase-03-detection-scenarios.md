# Phase 03 — Five Detection Scenarios

This phase implements and validates five independent attack scenarios, each with its own purpose-written Suricata rule supplementing ET Open. This document is built incrementally as each scenario is completed.

---

## Suricata Configuration Changes (Apply to All Scenarios)

Before Scenario 1, two configuration changes were made to `suricata.yaml` that affect detection across the whole phase, not just this scenario.

**`HOME_NET` narrowed:** from the original, broad definition (`192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12`) to `[10.10.10.0/24]` — precisely the protected LAN, per the [Phase 00 threat model](phase-00-planning.md#threat-model). Two new named network variables were added: `ATTACKER_NET: [192.168.50.99/32]` and `MGMT_NET: [192.168.50.10/32]`.

**Rationale:** under the old, broad `HOME_NET` definition (which also covered `192.168.50.0/24`), traffic from `attacker` was classified as `HOME_NET → HOME_NET` (internal), so any ET Open signature built on the `$EXTERNAL_NET -> $HOME_NET` pattern — the typical construction for most recon/exploit signatures in ET Open — could never match traffic from the attacker segment. Adding the separate `ATTACKER_NET`/`MGMT_NET` variables allows custom rules to target the attacker segment precisely, without risk of confusing attacker traffic with normal `mgmt` administrative traffic, which also physically sits in `$EXTERNAL_NET` after the narrowing.

**New local rules file:** `/var/lib/suricata/rules/local.rules`, registered in `suricata.yaml` (`rule-files: - suricata.rules / - local.rules`) — kept separate from `suricata.rules` (managed by `suricata-update`) so custom rules survive every future ET Open update.

**`attacker` VM preparation (predating Scenario 1):** DNS switched from external resolvers (`1.1.1.1`, `8.8.8.8`) to pfSense (`192.168.50.254`) for consistency with the rest of the lab, verified via `resolvectl status`. The temporary pfSense rule "unlimited access to Outside Network" used during tool installation was disabled (not deleted) once installation was complete — the same zero-standing-egress pattern established for Suricata in Phase 01.

---

## Scenario 1 — Port Scan (SYN Scan)

### Goal

Implement and validate detection of port-scan reconnaissance (SYN scan) from the `attacker` segment (OUTSIDE) toward the protected LAN, using a purpose-written Suricata rule.

### What Was Built

**Custom detection rule** (`sid:9000001`), added to `local.rules`:

```
alert tcp $ATTACKER_NET any -> $HOME_NET any (msg:"LOCAL Possible TCP SYN port scan from attacker segment"; flow:stateless; flags:S,12; threshold:type both, track by_src, count 10, seconds 5; classtype:attempted-recon; sid:9000001; rev:1;)
```

The rule matches TCP packets with the SYN flag from the attacker segment toward the protected LAN. The `threshold` clause limits alerting to a source generating 10 or more such packets within a 5-second window, avoiding a separate alert per individual SYN.

**Attack script** (`scripts/attacks/scenario-01-portscan.sh`): a host-discovery step (`nmap -sn`) was deliberately omitted — under the [Phase 00 threat model](phase-00-planning.md#scenario-a--north-south-perimeter), `attacker` already has knowledge of the network topology, so a ping sweep would be an unnecessary extra footprint with no reconnaissance value. The actual scan:

```
sudo nmap -sS -Pn -p 22,80,443,6443,10250 10.10.10.20 10.10.10.21 10.10.10.22 10.10.10.200 10.10.10.254 -T4
```

A SYN scan across 5 hosts × 5 deliberately chosen ports (SSH, HTTP/HTTPS, Kubernetes API, kubelet) — representing realistic, Kubernetes-aware targeted reconnaissance rather than a blind scan of an entire `/24`.

### Validation Results

- **Script runs deterministically and repeatably** — executed on two separate occasions (4 and 7 September) with an identical outcome: all ports report `filtered` on all five hosts, pfSense silently dropping `attacker → LAN` traffic.
- **Custom rule generates an alert with correct metadata** — confirmed in `eve.json`: `signature_id:9000001`, `signature:"LOCAL Possible TCP SYN port scan from attacker segment"`, `classtype` mapped to `category:"Attempted Information Leak"`, `severity:2`.
- **An additional, unplanned confirmation:** the same `HOME_NET` change also unblocked detection of the same traffic by an existing ET Open signature (`signature_id:2001219`, `"ET SCAN Potential SSH Scan"`), which could not fire against `attacker` traffic under the previous, broad `HOME_NET` definition. This is direct, measured evidence supporting the decision to narrow `HOME_NET`.
- **PCAP captured on `ens33`** — 50 SYN packets (5 hosts × 5 ports × 2 retransmission attempts due to no response), consistent with the expected port-scan pattern.

> **Note on evidence dates:** `scenario01-portscan-detected.pcap` and `scenario01-alerts.json` are both from the same capture window (7 September, 11:06:09–11:06:13 UTC) and correlate directly with each other. `scan-syn-02.txt` — the `nmap` output confirming all ports as `filtered` — is from an earlier, separate run of the same script (4 September). Both runs produced the same result, which supports the "deterministic and repeatable" validation criterion, but the three files are not a single, one-shot session; they represent two independent executions of the same test on different dates.

Evidence stored under `snapshots/phase-03/`:

| File | Content |
| --- | --- |
| `scenario01-portscan-detected.pcap` | Raw capture on `ens33`, 50 SYN-scan packets (7 September) |
| `scenario01-alerts.json` | Alerts from `eve.json` — the custom signature (`sid:9000001`) and the ET Open signature (`sid:2001219`) (7 September) |
| `scan-syn-02.txt` | `nmap` output from `attacker`, confirming `filtered` on all ports/hosts (4 September) |

### Problems Encountered and Resolutions

- **Incorrect `nmap` syntax with a comma-separated host list and no spaces** — `nmap` treated the entire list as a single, unresolvable hostname. Resolved by separating addresses with spaces (commas are only valid for port lists).
- **PCAP polluted by ambient traffic from the management SSH session itself** — the first filter (`host 192.168.50.99`) also matched the ongoing management session to `attacker`/`suricata`, not just scan traffic. Resolved by narrowing the filter to direction (`src host 192.168.50.99 and dst net 10.10.10.0/24`).
- **Ordering mismatch between starting `tcpdump` and running `nmap`** — the first capture attempt missed the intended traffic due to incorrect synchronisation between terminal windows. Resolved by establishing a strict order: confirm `listening on ens33...` first, only then run the traffic-generating command.
- **A faulty configuration insertion via an overly broad `sed` pattern** — `sed -i '/rule-files:/a...'` also matched an unrelated, commented-out `#rule-files:` line inside an experimental `firewall:` block further down the file, creating an invalid, orphaned YAML entry. Resolved by precisely removing only the faulty occurrence (a context-conditional `sed`, `n;/pattern/d`), confirmed via `suricata -T` before restarting the service.
- **The broad default `HOME_NET` definition** (see the configuration section above) limited ET Open's effectiveness against traffic from the `attacker` segment. Resolved by narrowing `HOME_NET` and introducing the dedicated `ATTACKER_NET`/`MGMT_NET` variables, with a confirmed positive side effect (unblocking an ET Open signature).

### Lessons Learned Entry

The following entry was added to [`docs/lessons-learned.md`](lessons-learned.md):

**Topic: The `HOME_NET` definition determines the effectiveness of the entire ruleset, not just custom rules.**

Previously unclear: whether a broad, "safe-looking" `HOME_NET` definition (covering the entire RFC1918 private address space) is neutral to Suricata's operation, or has a real effect on detection effectiveness.

What the exercise revealed: with `HOME_NET` covering both the attacker segment and the protected LAN, reconnaissance traffic was classified as "internal" (`HOME_NET → HOME_NET`), which meant a significant portion of ET Open signatures built on the `$EXTERNAL_NET -> $HOME_NET` pattern could not match this traffic at all — even though the engine technically saw every packet. Narrowing `HOME_NET` to the actually protected network immediately and measurably increased detection coverage, confirmed by a custom rule and an existing ET Open signature both firing on the same test traffic.

Takeaway: `HOME_NET`/`EXTERNAL_NET` are not just a documentation-level declaration of topology — they are an active parameter that determines which rules can match at all. These variables need to be set to reflect the network's actual trust model, not left at their defaults.

---

## Scenario 2 — HTTP Reconnaissance and Attack

### Goal

Detect a sequence of HTTP-based reconnaissance and attack techniques against a web service exposed on the protected LAN, using Suricata rules built on both request metadata (User-Agent) and URL content.

### What Was Built

- A new namespace, `phase03-http-target`, running `nginx`, exposed via a Cilium L2 VIP (`10.10.10.201`), assigned automatically from `k8s-lan-pool` once the required `lb-ipam: lan` label was applied to the `Service` (see Problems Encountered below).
- A dedicated pfSense rule permitting `attacker → 10.10.10.201:80`, scoped narrowly to this scenario.
- Three custom rules added to `local.rules`:
  - `sid:9000002` — matches a Nikto-style scanner `User-Agent`.
  - `sid:9000003` — matches a request to a sensitive path (`/.env`).
  - `sid:9000004` — matches a path-traversal attempt, corrected from `http.uri` to `http.uri.raw` after discovering Suricata's default URI buffer is normalised (see Problems Encountered below).

### Validation Results

- **All three custom rules fired with correct metadata**, confirmed in `eve.json`: `sid:9000002` (`"LOCAL Nikto-style web scanner User-Agent detected"`, 6 occurrences), `sid:9000003` (`"LOCAL Suspicious request to sensitive path"`, 2 occurrences), `sid:9000004` (`"LOCAL Path traversal attempt detected"`, 2 occurrences).
- **Four ET Open signatures also fired on the same traffic** — direct further confirmation of the `HOME_NET` narrowing from the Suricata Configuration Changes section: `ET SCAN Nikto Web App Scan in Progress`, `ET INFO Request to Hidden Environment File - Inbound`, `ET WEB_SERVER /etc/passwd Detected in URI`, `ET WEB_SERVER /etc/shadow Detected in URI` — 21 alert events in total across the seven signatures.
- PCAP captured on `ens33`: `scenario02-http-attack.pcap` (the Nikto-UA and sensitive-path requests) and `scenario02-path-traversal-raw.pcap` (the path-traversal attempt specifically, captured separately to isolate the raw, un-normalised request on the wire).

Evidence stored under `snapshots/phase-03/`: `scenario02-http-attack.pcap`, `scenario02-path-traversal-raw.pcap`, `scenario02-alerts.json`.

### Problems Encountered and Resolutions

- **Missing required `lb-ipam: lan` label on the `Service`** — `EXTERNAL-IP` stayed `<pending>` with no `Events` at all, because the `k8s-lan-pool` IP pool's `serviceSelector` silently rejected services that didn't match it. Resolved after identifying the `serviceSelector` in the pool's configuration and adding the matching label.
- **`curl` normalises `../` before sending the request** — the path-traversal payload never reached the network in its literal form. Resolved with `curl --path-as-is`.
- **Suricata's `http.uri` buffer is normalised, not raw** — rule `sid:9000004` failed to match the literal `../` despite correct traffic on the wire. Resolved by switching the rule to `http.uri.raw`.

---

## Scenario 3 — Suspicious DNS Traffic

### Goal

Detect DNS-based reconnaissance/exfiltration-style traffic using both content-based and volume-based detection.

### What Was Built

- A loop of 20 queries to random subdomains of `exfil-test.example.com` — the test domain was corrected from a `.local` TLD after discovering it was being intercepted locally by mDNS rather than reaching the network as ordinary DNS (see Problems Encountered).
- Two custom rules added to `local.rules`:
  - `sid:9000005` — matches on the exfil-test domain content.
  - `sid:9000006` — a volume-based threshold rule, independent of query content: 15 or more queries from a single source within 5 seconds.

### Validation Results

- **Both rules fired with correct metadata**: `sid:9000005` (`"LOCAL Suspicious DNS query to known exfil domain"`) fired 21 times, consistent with the 20-query test loop; `sid:9000006` (`"LOCAL Possible DNS tunneling - high volume queries from single source"`) fired once, consistent with a single threshold breach across the burst.
- PCAP captured on `ens33`: 20 packets in `scenario03-dns-tunneling.pcap`, spanning the roughly 5-second test window.

Evidence stored under `snapshots/phase-03/`: `scenario03-dns-tunneling.pcap`, `scenario03-alerts.json`.

### Problems Encountered and Resolutions

- **Test domain (`.local`) intercepted locally by mDNS** — queries never left `attacker` as ordinary DNS. Resolved by switching to `.example.com`, an IANA-reserved test domain.
- **Ordering mismatch between starting the capture and running the test loop** — the same class of issue as in Scenario 1, resolved the same way: confirm the capture is active before generating traffic.

---

## Scenario 4 — Attempt Blocked by pfSense

### Goal

Correlate a single, deterministic blocked connection attempt across two independent evidence sources — the pfSense firewall log and the Suricata `eve.json` flow record — to the same 5-tuple and timestamp.

### What Was Built

A single, deliberate connection attempt from `attacker` to `k8s-master:22` (`nc -zv 10.10.10.20 22`), with no corresponding pfSense allow rule in place.

### Validation Results

- **Full 5-tuple and timestamp agreement** between the two independent sources, confirmed to the second:
  - pfSense `filter.log`: `Sep 8 08:38:14`/`08:38:15`, `Default deny rule IPv4 (1000000103)`, `192.168.50.99:41380 → 10.10.10.20:22`, `TCP:S`.
  - Suricata `eve.json` (`ens33`): `flow.start: 2026-09-08T08:38:14.546734Z`, `flow.end: ...15.564325Z`, same source/destination and ports, `tcp.syn: true`.
- The pfSense web UI log view (screenshot) shows the same two entries alongside unrelated blocked traffic from earlier in the session, confirming the deny rule and timestamps match what's recorded in `filterlog.txt`.

Evidence stored under `snapshots/phase-03/`: `scenario04-pfsense-block.pcap` (2 packets, the SYN retransmit pair), `scenario04-filterlog.txt`, `scenario04-pfsense-filterlog.png`, `scenario04-suricata-flow.json`.

> **Note:** `scenario04-filterlog.txt` is a raw excerpt of pfSense's firewall log covering several hours and includes earlier, unrelated blocked traffic from prior debugging sessions (an HTTP connectivity check, blocked outbound NTP, an earlier SSH attempt at `08:21`). Only the `08:38:14`–`08:38:15` pair is the correlated evidence for this scenario; the rest is retained in the file as-is rather than trimmed.

### Problems Encountered and Resolutions

- **Ordering/synchronisation between starting the capture and running the test** — the same recurring class of issue as in Scenarios 1 and 3, resolved the same way.

---

## Scenario 5 — Attempt Blocked by CiliumNetworkPolicy

### Goal

Demonstrate and correlate a lateral-movement attempt blocked at the Cilium policy layer, contrasted against a permitted connection from a trusted pod to the same target, and document how this evidence differs in kind from the pfSense-based correlation in Scenario 4.

### What Was Built

- A new namespace, `phase03-lateral-movement`, with two pods on `k8s-worker2`: `attacker-pod` (no label) and `trusted-client` (`role: trusted`).
- A `CiliumNetworkPolicy` in `phase03-http-target`, restricting ingress to `phase03-webserver` to pods labelled `role: trusted` in the `phase03-lateral-movement` namespace — which required an explicit namespace selector in `fromEndpoints` (see Problems Encountered below).
- A contrast test: `attacker-pod` and `trusted-client` both attempt a connection to `phase03-webserver`, in the same time window.

### Validation Results

- **123 VXLAN packets** (100% UDP/8472, `10.10.10.21` ↔ `10.10.10.22`) captured on `ens34` (`scenario05-cnp-block.pcap`), confirming Suricata saw the full envelope of both the denied and the permitted attempts — but, consistent with the Phase 02 finding on VXLAN opacity, with no visibility into the policy decision itself.
- **Hubble shows a clear, correlated verdict split.** Filtered to traffic between `attacker-pod`/`trusted-client` and `phase03-webserver` (`hubble-scenario05-filtered.json`, 36 of 38 raw entries — 2 unrelated `TRACED` entries excluded):
  - 10 of 11 connection attempts from `attacker-pod` resulted in a `DROPPED` verdict. The first SYN in the sequence (`10:34:46.4775`) was recorded once as `FORWARDED`, roughly 19 ms before the first `DROPPED` verdict on the same flow — an observation consistent with a known pattern in connection-tracking/eBPF-based enforcement, where the first packet of a new flow can pass before the policy decision is fully applied to connection tracking, after which subsequent packets on the same flow are consistently dropped. This has not been independently confirmed against Cilium's own internals (for example, via `cilium monitor`) and is documented here as an observation with a plausible explanation, not a verified mechanism.
  - `trusted-client`, in the same time window, obtained full, unimpeded access: 12 `FORWARDED` events covering a complete TCP connection lifecycle (SYN → ACK → PSH,ACK → FIN,ACK).
- **An architectural finding specific to this scenario:** the pfSense-based correlation used in Scenario 4 does not apply here — pfSense never sees pod-to-pod traffic within the same LAN subnet, since cross-node pod traffic travels directly over VXLAN between workers at L2, without passing through the gateway. The evidentiary basis for this scenario is therefore Hubble (primary) plus Suricata on `ens34` (supplementary, with the VXLAN caveat from Phase 02) — with no pfSense involvement, which reflects the actual network topology rather than a gap in the test.

Evidence stored under `snapshots/phase-03/`: `scenario05-cnp-block.pcap`, `hubble-scenario05.json` (raw), `hubble-scenario05-filtered.json` (filtered to the relevant flows).

### Problems Encountered and Resolutions

- **`CiliumNetworkPolicy` defaults `fromEndpoints` to the policy's own namespace** — despite the correct `role: trusted` label, `trusted-client` (in a different namespace to the policy) was incorrectly blocked alongside `attacker-pod`. Resolved by adding an explicit `k8s:io.kubernetes.pod.namespace` selector in `fromEndpoints` — a documented, common pitfall when writing cross-namespace policies.
- **The `phase02-traffic-test` namespace had already been removed** during Phase 02 cleanup, requiring a new, dedicated `trusted-client` rather than reusing the pod from the previous phase.

---

## Overall Validation Summary

All validation criteria from [Phase 00](phase-00-planning.md#phase-03--five-detection-scenarios) were met across all five scenarios:

- Every attack script runs deterministically and repeatably.
- All six custom signatures (`sid:9000001`–`9000006`) fire with correct `sid`/`classtype`/`severity` metadata.
- Narrowing `HOME_NET` demonstrably unblocked multiple ET Open signatures, confirmed independently in both Scenario 1 and Scenario 2.
- Scenario 4 achieved full 5-tuple/timestamp correlation between pfSense and Suricata.
- Scenario 5 achieved a clear Hubble-based verdict correlation, with an additional, documented observation about verdict timing on the first packet of a denied flow, and a documented architectural reason why pfSense correlation does not apply to this scenario.

## Lessons Learned Entry

The following entry was added to [`docs/lessons-learned.md`](lessons-learned.md):

**Topic: Client-side and intermediary tools can "clean up" attack traffic before it reaches the network — detection testing has to be verified on the wire, not just by the intent of the command.**

Previously unclear: whether issuing a command that contains an attack pattern (for example, `../` in a URL, a query to `.local`) guarantees that exact pattern actually appears on the wire.

What the exercise revealed: three separate times in this phase, an intermediary tool altered the intended payload before it was sent — `curl` normalised `../` in the URL, `systemd-resolved` intercepted `.local` locally via mDNS, and `CiliumNetworkPolicy` defaulted its selector scope to its own namespace, contrary to an intuitive reading of the rule. In each case, only direct PCAP inspection or an explicit override (`--path-as-is`, changing the TLD, an explicit namespace selector) revealed the actual behaviour.

Takeaway: writing and testing detection rules requires a standing habit of verifying at the raw-traffic level (PCAP, `tcpdump -A`) rather than trusting what a command was intended to do — client tools, resolvers, and policy engines have their own, sometimes non-obvious normalising or scoping behaviour that can silently invalidate a test's assumptions.

---

*All five scenarios complete.*

