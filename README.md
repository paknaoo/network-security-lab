# network-security-lab

> A Suricata-based intrusion detection lab observing an existing Kubernetes networking environment from a security perspective, covering perimeter and lateral-movement detection, manual evidence correlation and IDS-to-IPS tuning.

This repository documents the design, deployment and validation of a network intrusion detection and investigation capability built on top of an existing lab environment. The project focuses on detection engineering, traffic analysis and manual incident correlation, following the same structured, phase-by-phase implementation approach used in the author's previous labs.

The environment is being built incrementally, with each phase documented and validated before the next is introduced. This repository documents only capabilities that have been implemented and validated in the lab.

This is the third project in a deliberate learning arc: [`zabbix-noc-lab`](https://github.com/paknaoo/zabbix-noc-lab) (build/monitor infrastructure) → [`k8s-cilium-lab`](https://github.com/paknaoo/k8s-cilium-lab) (build and observe Kubernetes networking) → `network-security-lab` (detect, investigate and respond to security incidents).

---

## Related Infrastructure

This lab observes infrastructure provisioned in a separate portfolio project, [k8s-cilium-lab](https://github.com/paknaoo/k8s-cilium-lab) — a production-inspired Kubernetes networking environment built with VMware Workstation, pfSense and Cilium. `network-security-lab` is deliberately a standalone repository: it treats the existing lab as a fixed target of observation rather than extending that project's scope.

| Host / Component | IP address | Role in this lab |
| --- | --- | --- |
| pfSense | `192.168.50.254` / `10.10.10.254` | Perimeter firewall between OUTSIDE and Kubernetes LAN |
| k8s-master | `10.10.10.20` | Observed target |
| k8s-worker1 | `10.10.10.21` | Observed target |
| k8s-worker2 | `10.10.10.22` | Observed target (powered on ad hoc) |
| mgmt | `192.168.50.10` | Management workstation |
| **suricata** (new) | `192.168.50.30` (eth0), `10.10.10.30` (eth1) | IDS engine, dual-tap |
| **attacker** (new) | `192.168.50.99` | North-south attacker VM |
| **attacker-pod** (new) | dynamic (Cilium IPAM) | East-west attacker pod |

---

## Architecture

The following diagram provides a high-level overview of the lab environment and its relationship to the existing Kubernetes networking lab.

```mermaid
flowchart TD

    HOST[Windows Host]
    VMW[VMware Workstation]

    subgraph NAT["VMnet8 — NAT / WAN"]
        INTERNET[Internet]
    end

    subgraph OUTSIDE["VMnet11 — OUTSIDE (192.168.50.0/24)"]
        MGMT[mgmt]
        ATTACKER[attacker]
        SURI_OUT[suricata eth0 - tap]
    end

    subgraph FIREWALL["pfSense"]
        PFSENSE[Firewall / Router]
    end

    subgraph LAN["VMnet10 — Kubernetes LAN (10.10.10.0/24)"]
        MASTER[k8s-master]
        WORKER1[k8s-worker1]
        WORKER2[k8s-worker2]
        SURI_LAN[suricata eth1 - tap]
    end

    subgraph IDS["Suricata VM"]
        ENGINE[Suricata engine]
    end

    HOST --> VMW
    VMW --> MGMT
    VMW --> ATTACKER
    VMW --> ENGINE
    VMW --> PFSENSE
    VMW --> MASTER
    VMW --> WORKER1
    VMW --> WORKER2

    INTERNET --> PFSENSE
    ATTACKER -.->|attack traffic| PFSENSE
    MGMT --> PFSENSE
    PFSENSE --> MASTER
    PFSENSE --> WORKER1
    PFSENSE --> WORKER2

    SURI_OUT -.-> ENGINE
    SURI_LAN -.-> ENGINE
```

> This diagram will be finalised in Phase 09 to reflect the fully implemented and validated lab. See [Phase 00 — Planning](docs/phase-00-planning.md) for the full architecture rationale and threat model.

---

## Project Goals

The project is designed to build practical experience with detection engineering and incident investigation while documenting each completed implementation phase.

- Deploy Suricata as a dual-tap IDS observing both perimeter (pre-firewall) and internal (post-firewall, east-west) traffic.
- Design and validate independent attack scenarios, each with a purpose-written detection rule.
- Practise manual, multi-source log correlation (Suricata, pfSense, Hubble) without SIEM assistance.
- Deepen understanding of harder Kubernetes networking mechanisms (BGP Control Plane v2, L2 Announcements) by observing their behaviour under attack conditions.
- Practise a full incident-response cycle, including handling a deliberate false positive.
- Deliberately and separately transition the IDS from pure detection to inline blocking (IPS), with documented rule-selection criteria.
- Maintain concise, reproducible infrastructure and investigation documentation suitable for a technical portfolio.

---

## Technology Stack

The following technologies are used throughout the project.

| Category | Technology |
| --- | --- |
| Operating System | Ubuntu Server 24.04 LTS |
| IDS / IPS Engine | Suricata (af-packet, multi-interface) |
| Ruleset | Emerging Threats Open (via `suricata-update`) + custom rules |
| Traffic Analysis | tcpdump, Wireshark, PCAP |
| Kubernetes Observability | Cilium Hubble (CLI and UI) |
| Perimeter Firewall | pfSense CE |
| Attacker Tooling | `nmap`, `curl`, `dig`, `hping3` (via `nicolaka/netshoot` for the pod-based attacker) |
| Correlation | Manual, cross-source (Suricata `eve.json`, pfSense logs, Hubble UI) — no SIEM |
| Source Control | Git and GitHub |

---

## Implemented Components

This section will be updated as each phase is completed and validated.

- [x] Phase 00 — Planning, architecture and threat model finalised.
- [x] Phase 01 — Suricata IDS deployment.
- [x] Phase 02 — Traffic analysis (tcpdump, Wireshark, PCAP, Hubble UI).
- [x] Phase 03 — Five detection scenarios with custom rules.
- [x] Phase 04 — Evidence correlation (pfSense + Suricata + Hubble UI).
- [x] Phase 05 — Multi-event manual timeline reconstruction.
- [x] Phase 06 — Full incident investigations, including a false positive.
- [ ] Phase 07 — IDS → IPS transition with rule tuning.
- [ ] Phase 09 — Final validation, architecture diagram, README, CV talking points.

Phase 08 (SIEM) is deliberately skipped — see [Phase 00 — Planning](docs/phase-00-planning.md#phase-08--skipped).

---

## Documentation

Implementation details are organised by project phase. Phases are listed in planned order; only completed phases are linked.

1. [Phase 00 — Planning](docs/phase-00-planning.md)
2. [Phase 01 — Suricata IDS Deployment](docs/phase-01-suricata-deployment.md)
3. [Phase 02 — Traffic Analysis](docs/phase-02-traffic-analysis.md)
4. [Phase 03 — Five Detection Scenarios](docs/phase-03-detection-scenarios.md)
5. [Phase 04 — Evidence Correlation](docs/phase-04-evidence-correlation.md)
6. [Phase 05 — Log Correlation, Manual Timeline Reconstruction](docs/phase-05-log-correlation.md)
7. [Phase 06 — Full Incident Investigations](docs/phase-06-incident-investigations.md)
   - [Case 1 — Multi-Stage Reconnaissance and Access Attempt](docs/incident-reports/case-01-multistage-recon.md)
   - [Case 2 — DNS Exfiltration Pattern and Lateral Movement](docs/incident-reports/case-02-dns-lateral.md)
   - [Case 3 — False Positive Analysis and Rule Tuning](docs/incident-reports/case-03-false-positive-tuning.md)

The detailed lessons-learned log, capturing concept-level takeaways as they are encountered, is maintained in:

- [Lessons Learned](docs/lessons-learned.md)

---

## Validation

Validation is grouped by phase and updated as each phase is completed.

Phase 00 is planning and research only and is not subject to formal validation — see [Phase 00 — Planning](docs/phase-00-planning.md).

**Phase 01 — Suricata IDS Deployment:** all criteria met — service active and stable, both `af-packet` interfaces (`ens33`, `ens34`) independently confirmed via packet counters and a controlled ICMP test, ET Open ruleset loaded (68,643 rules, 52,691 active), and pure IDS mode confirmed via engine logs. Full detail in [Phase 01](docs/phase-01-suricata-deployment.md#validation-results).

**Phase 02 — Traffic Analysis:** all criteria met — PCAP captured and correctly interpreted on both taps across three scenarios (plaintext, VXLAN-encapsulated, WireGuard-encrypted), Hubble confirmed showing the same class of traffic with full pod identity, and a concrete, three-level visibility difference documented between Suricata's two taps and Hubble. Full detail in [Phase 02](docs/phase-02-traffic-analysis.md#validation-results).

**Phase 03 — Five Detection Scenarios:** all criteria met — six custom Suricata signatures across port scan, HTTP recon/attack, and DNS-tunneling detection, each with correct alert metadata; narrowing `HOME_NET` independently confirmed to unblock multiple ET Open signatures; full 5-tuple/timestamp correlation between pfSense and Suricata for a blocked north-south attempt; and a Hubble-based verdict correlation for a blocked lateral-movement attempt, contrasted against a permitted connection from a trusted pod. Full detail in [Phase 03](docs/phase-03-detection-scenarios.md#overall-validation-summary).

**Phase 04 — Evidence Correlation:** all criteria met, extended to two scenarios instead of one — a second-level timeline reconstruction correlating pfSense's `filterlog` with Suricata's `eve.json` for a north-south block, a microsecond-level Hubble-based reconstruction for an east-west CiliumNetworkPolicy block (with Suricata's VXLAN tap as supplementary, non-attributable volume evidence), and a visibility matrix documenting which evidence source has insight into which traffic type, and why. Full detail in [Phase 04](docs/phase-04-evidence-correlation.md#validation-results).

**Phase 05 — Log Correlation, Manual Timeline Reconstruction:** all criteria met — five events reconstructed into a single chronology across a 57-minute window, spanning all four evidence sources, with 11 of 49 Suricata alerts (~22%) explicitly identified and documented as noise from an unrelated, concurrent infrastructure incident, and the time/effort of manual correlation documented (100+ minutes, nearly half spent on the side incident) as a reference point for the value of SIEM at scale. Full detail in [Phase 05](docs/phase-05-log-correlation.md#validation-results).

**Phase 06 — Full Incident Investigations:** all criteria met — two SOC/IR-style incident reports (multi-stage recon/access, and DNS exfiltration pattern + lateral movement), each applying a three-tier Observed/Assessed/Not-observed confidence discipline with an explicit attempted-vs-successful distinction; plus a full false-positive tuning cycle on `sid:9000001` (root cause → `rev:2` fix → live validation confirming the genuine scan still alerts while the blocked-connection false positive is eliminated). Full detail in [Phase 06](docs/phase-06-incident-investigations.md#validation-results).

Further phases will be added here as they are completed.

---

## Project Status

This project is **in progress**. Phases 00–06 (planning, Suricata deployment, traffic analysis, five detection scenarios, evidence correlation, multi-event timeline reconstruction, and full incident investigations) are complete; Phase 07 (IDS → IPS transition) is next.

---

## Licence

This project is licensed under the MIT Licence. See the `LICENSE` file for details.
