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

*Scenarios 2–5 to follow.*
