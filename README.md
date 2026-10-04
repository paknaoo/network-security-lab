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

The diagram below shows the lab as built and validated — in particular, the two attacker vantage points that were tested and the three independent evidence sources used to investigate them. No single source sees everything: that gap is the central finding of the project.

```mermaid
flowchart TB

    subgraph OUTSIDE["VMnet11 — OUTSIDE (192.168.50.0/24)"]
        MGMT["mgmt · .10<br/>management, sole SSH initiator"]
        ATTACKER["attacker · .99<br/>north-south attacker"]
    end

    PFSENSE["pfSense · OUTSIDE .254 / LAN .254"]

    subgraph LAN["VMnet10 — Kubernetes LAN (10.10.10.0/24)"]
        NODES["k8s-master .20 · worker1 .21 · worker2 .22<br/>service VIPs .200 / .201 (L2 / BGP)"]
        subgraph CLUSTER["Cilium CNI workloads"]
            ATTACKERPOD["attacker-pod<br/>east-west attacker (unprivileged)"]
            TARGET["phase03 targets<br/>webserver / internal-service"]
        end
    end

    subgraph EVIDENCE["Three independent evidence sources"]
        PF_LOG["1 · pfSense filterlog<br/>what crossed the segment boundary"]
        SURICATA["2 · Suricata engine (dual af-packet tap)<br/>ens33 pre-filter: attempts, pre-decision<br/>ens34 post-filter: permitted + VXLAN envelope only<br/>ET Open + 6 custom rules · IDS 01–06 · inline/NFQUEUE 07"]
        HUBBLE["3 · Cilium Hubble (eBPF)<br/>pod identity + DROPPED/FORWARDED verdict<br/>Cilium datapath only"]
    end

    MGMT -->|"WireGuard full tunnel"| PFSENSE
    ATTACKER -.->|"N-S attack: scan / HTTP / DNS / SSH"| PFSENSE
    PFSENSE --> NODES
    ATTACKERPOD -.->|"E-W attack: cross-namespace"| TARGET

    PFSENSE -. observed by .-> PF_LOG
    OUTSIDE -. tapped by .-> SURICATA
    LAN -. tapped by .-> SURICATA
    CLUSTER -. observed by .-> HUBBLE

    classDef evidence fill:#1f2937,stroke:#60a5fa,color:#e5e7eb
    class PF_LOG,SURICATA,HUBBLE evidence
```

> See [Phase 00 — Planning](docs/phase-00-planning.md#architecture-diagram) for the original planning diagram and the full architecture rationale and threat model, and [Phase 08](docs/phase-08-final-validation.md#as-built-architecture-diagram) for the as-built diagram in context.

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
- [x] Phase 07 — IDS → IPS transition with rule tuning.
- [x] Phase 08 — Final validation, architecture diagram, README, CV talking points.

SIEM (Wazuh) was deliberately excluded from scope due to host RAM budget constraints — see [Phase 00 — Planning](docs/phase-00-planning.md#project-goal-and-relationship-to-k8s-cilium-lab).

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
8. [Phase 07 — IDS → IPS Transition](docs/phase-07-ids-ips-transition.md)
9. [Phase 08 — Final Validation, Architecture Diagram, CV Talking Points](docs/phase-08-final-validation.md)

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

**Phase 07 — IDS → IPS Transition:** all criteria met — Suricata run inline via NFQUEUE on an isolated test path, confirmed blocking real traffic (not just alerting) with a content-based `drop` rule while a sibling `alert` rule and benign traffic passed through, verified in one time window (engine verdict totals: 52 dropped, 20 accepted); the main IDS service and SSH stayed up throughout. Full detail in [Phase 07](docs/phase-07-ids-ips-transition.md#validation-results).

**Phase 08 — Final Validation:** every prior phase re-checked against its own criteria and the live repository state — all pass. Two Phase 00 criteria carried honest scope notes rather than silent passes: attacks were documented as inline commands in the phase docs rather than committed as a full script harness (one representative script is committed and syntax-clean), and Phase 06 has no separate snapshots by design (its investigations are built on Phase 05 evidence). The as-built architecture diagram and CV talking points were produced in this phase. Full detail in [Phase 08](docs/phase-08-final-validation.md#final-re-validation).

---

## Project Status

This project is **complete**. All phases (00–08) are implemented, validated, and documented: planning, Suricata deployment, traffic analysis, five detection scenarios, evidence correlation, multi-event timeline reconstruction, full incident investigations, the IDS → IPS transition, and final validation.

---

## Talking Points

Each point below is backed by committed evidence in this repository, not by assertion.

- **Dual-tap Suricata IDS** (v8.0.6, `af-packet`) positioned to observe traffic both before and after a pfSense firewall decision — demonstrating the pre- vs. post-filter sensor-placement trade-off with captured evidence from both vantage points.
- **Six custom Suricata signatures** supplementing ET Open, including a full false-positive tuning cycle (root cause → rule revision → live before/after validation) that eliminated a 10/11 false-positive rate without losing true-positive detection.
- **Manual, multi-source incident correlation** across three independent evidence sources (pfSense, Suricata, Cilium Hubble) without a SIEM — reconstructing second-level timelines and quantifying the analyst effort involved as a concrete argument for correlation automation at scale.
- **Real incident diagnosis under ambiguity** — two conflicting CiliumNetworkPolicies on a shared pod, overlapping in time with a genuine L2-announcement infrastructure fault, resolved by systematic hypothesis elimination across ARP, firewall state, packet capture, and eBPF flow logs.
- **IDS → inline IPS transition** (NFQUEUE) on an isolated path, confirming real packet blocking with documented drop-vs-alert rule-qualification criteria, while keeping the production IDS and management access untouched.
- **A consistent validation discipline throughout** — every quoted figure verified programmatically against source evidence, with limitations and corrections stated openly rather than quietly cleaned up.

See [Phase 08](docs/phase-08-final-validation.md#cv-talking-points) for the same points tied to their specific phases.

---

## Licence

This project is licensed under the MIT Licence. See the `LICENSE` file for details.
