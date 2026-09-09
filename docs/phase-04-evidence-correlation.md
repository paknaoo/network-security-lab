# Phase 04 — Evidence Correlation (pfSense + Suricata + Hubble UI)

This phase builds a consistent, manual correlation workflow across independent evidence sources for events from Phase 03, explicitly documenting visibility discrepancies between tools rather than omitting them.

---

## Goal

Reconstruct "who saw what and when" for selected Phase 03 events using multiple independent evidence sources, and document any gaps in visibility as findings in their own right.

---

## What Was Built

The scope was deliberately widened beyond the single scenario suggested in [Phase 00](phase-00-planning.md#phase-04--evidence-correlation-pfsense--suricata--hubble-ui) ("ideally #5") to cover **two** scenarios in parallel — Scenario 4 (pfSense + Suricata, north-south traffic) and Scenario 5 (Suricata + Hubble, east-west traffic) — because Phase 03 established that pfSense has no physical visibility into pod-to-pod traffic within a single LAN segment, making a genuine three-way pfSense/Suricata/Hubble correlation impossible for Scenario 5 alone.

- The Hubble UI SSH tunnel (`ssh -L 12000:127.0.0.1:12000 master`, `cilium hubble ui`) was re-established after expiring since Phase 02.
- Scenario 5's test traffic was regenerated with the Hubble UI open live in the browser, producing a service map that confirms the cross-namespace topology (`phase03-lateral-movement` → `phase03-http-target`) with a visual distinction between `DROPPED` and `FORWARDED` verdicts.
- Two timeline correlation tables were built (Scenario 4, Scenario 5), joining independent evidence sources by 5-tuple/identity and timestamp.
- A visibility matrix was built, synthesising which evidence source has insight into which type of traffic, and why.

---

## Scenario 4 — Timeline Reconstruction (pfSense + Suricata)

| Time (UTC) | Source | Event | Detail |
| --- | --- | --- | --- |
| `08:38:14.546734` | Suricata (`ens33`, pre-filter) | `flow.start` — first SYN recorded | `src: 192.168.50.99:41380 → dst: 10.10.10.20:22`, `tcp_flags:02` (SYN), `state:syn_sent` |
| `08:38:14` | pfSense (`filterlog`, `em1`/OUTSIDE) | First SYN blocked | `Default deny rule IPv4 (1000000103)`, `192.168.50.99:41380 → 10.10.10.20:22`, IP ID `60040`, TCP seq `4219246736` |
| `08:38:15` | pfSense (`filterlog`) | SYN retransmission blocked | Same 5-tuple and seq, IP ID `60041` (incremented by 1 — confirms the same session, not a new attempt) |
| `08:38:15.564325` | Suricata (`ens33`) | `flow.end` — flow closed | `pkts_toserver:2` (original SYN + retransmission), `reason:timeout`, `alerted:false` |
| `08:39:23.259107` | Suricata (`eve.json`, write) | `flow` entry actually written to the log | ~68-second delay relative to `flow.end` — consistent with the Phase 02 finding that Suricata buffers a closed flow before writing it |

**Key correlation confirmations:**

1. **Identical 5-tuple in both sources**: `192.168.50.99:41380 → 10.10.10.20:22, TCP` — no ambiguity about the event's identity.
2. **Second-level time agreement**: Suricata's `flow.start` (`08:38:14.546734`) aligns with pfSense's first block entry (`08:38:14`).
3. **Matching attempt count on both sides**: 2 SYN packets at Suricata = 2 blocked entries in the pfSense `filterlog`.

**Visibility discrepancy:**

- **Time precision differs**: pfSense's `filterlog` logs to second-level precision, Suricata's `eve.json` to microsecond precision. "Second-level" correlation is the maximum precision the weaker of the two sources allows.
- **Suricata did not generate an alert** for this event (`alerted:false`) — neither the custom rule `sid:9000001` (a 10+-in-5-seconds threshold, versus only 2 attempts here) nor ET signature `2001219` fired against a single, low-volume attempt. The correlation here relies on the raw `flow` record, not an alert.
- **`eve.json` write delay** (68 seconds from `flow.end` to disk) means that, in a near-real-time correlation, the pfSense log would be available for analysis well before the corresponding Suricata entry.

**Evidence sources:** `scenario04-filterlog.txt`, `scenario04-suricata-flow.json`, `scenario04-pfsense-block.pcap`, `scenario04-pfsense-filterlog.png` (all in `snapshots/phase-03/`).

---

## Scenario 5 — Timeline Reconstruction (Suricata + Hubble)

| Time (UTC) | Source | Event | Detail |
| --- | --- | --- | --- |
| `10:34:46.4738` | Hubble | `attacker-pod → coredns` | Service-name DNS resolution, `FORWARDED` |
| `10:34:46.4776` | Hubble | `attacker-pod → phase03-webserver`, first SYN | `FORWARDED` — the packet passed before the policy decision on the destination node (`k8s-worker1`) was fully applied |
| `10:34:46.4962`–`10:34:50.6262` | Hubble | 10× SYN retransmission, `attacker-pod → phase03-webserver` | All `DROPPED` — consistently rejected once the policy decision was established in connection tracking |
| `10:34:51.6093`–`10:34:51.6395` | Hubble | `trusted-client → phase03-webserver`, full TCP cycle (×2) | **11 events**, all `FORWARDED` (SYN → SYN-ACK → ACK → PSH → FIN, twice) |
| (entire test window) | Suricata (`ens34`, LAN tap) | 123 UDP/8472 (VXLAN) packets | Recorded as an opaque envelope between `10.10.10.21`/`10.10.10.22` — no distinction as to which packet corresponds to which pod or verdict |

**Key correlation confirmations:**

1. **Volume consistent by order of magnitude**: 123 VXLAN packets comfortably cover 11 `attacker-pod` attempts (mostly single SYNs) plus 2 full TCP handshakes from `trusted-client` plus the accompanying DNS queries — consistent, though not attributable 1:1 without decapsulation.
2. **Cilium's enforcement point sits on the destination node, not the source node**: confirmed by the single `FORWARDED` verdict on `attacker-pod`'s first SYN, recorded before the `deny` decision was fully applied.

**Visibility discrepancy:**

- **pfSense does not feature in this correlation at all** — `k8s-worker2 → k8s-worker1` traffic stays entirely within `10.10.10.0/24` and never passes through the gateway. This is a genuine physical-topology limitation, not a gap in the test — the original validation criterion in [Phase 00](phase-00-planning.md) (assuming a three-way pfSense+Suricata+Hubble correlation for Scenario 5 as well) does not apply to intra-LAN traffic.
- **Suricata on `ens34` cannot distinguish the policy verdict** — it sees 123 UDP/8472 packets as a uniform stream, with no way to determine from the PCAP alone which packets correspond to denied attempts versus permitted traffic. This distinction is visible only in Hubble.
- **Suricata generated no alert at all** for this traffic — all cross-node VXLAN traffic is outside the reach of L4–L7 signatures, consistent with the limitation documented in Phase 02.
- **A timing asymmetry between sources**: Hubble provides microsecond timestamps with immediate recording (`--follow`), while Suricata's PCAP requires manual offline analysis.

**Evidence sources:** `hubble-scenario05.json`, `hubble-scenario05-filtered.json`, `scenario05-cnp-block.pcap` (in `snapshots/phase-03/`); `scenario05-hubble-servicemap-attacker-blocked.png`, `scenario05-hubble-servicemap-trusted-allowed.png`, `scenario05-hubble-servicemap-cross-namespace-topology.png` (in `snapshots/phase-04/`).

---

## Visibility Matrix — Synthesis

| Evidence source | Scenario 4 (north-south, pfSense block) | Scenario 5 (east-west, CiliumNetworkPolicy block) |
| --- | --- | --- |
| pfSense | Full visibility — logs every attempt and block decision, with the 5-tuple | Absent — traffic never reaches the gateway (same L2 segment) |
| Suricata | Sees the attempt (flow), but generates no alert at low volume (threshold not reached) | Sees only an opaque VXLAN envelope — zero L4–L7 insight, zero verdict distinction |
| Hubble | Not usable for this traffic — host-to-host SSH never passes through Cilium's pod datapath (established in Phase 02) | Full visibility — identity, `DROPPED`/`FORWARDED` verdict, exact enforcement point |

**Synthesis:** no single source has full visibility into the whole environment — an unavoidable consequence of where each tool physically observes traffic.

- **pfSense** sees only what crosses a network segment boundary (OUTSIDE↔LAN) — blind to anything happening within a single segment.
- **Suricata** sees everything on the wire at its two taps, but its understanding is limited to what it can decode — encapsulation (VXLAN) and low-volume attempts below a rule's threshold remain partially or fully opaque to it.
- **Hubble** has the deepest insight (identity, L7, policy decisions), but only for traffic that passes through Cilium's datapath — host-to-host traffic is entirely outside its reach.

**Practical consequence:** none of these tools can be the sole source of truth. A complete picture of an incident requires a deliberate choice of which source to query depending on the type of traffic (north-south vs east-west, host-to-host vs pod-to-pod, encapsulated vs plaintext) — the difference between owning three tools and owning a correlation process that knows which tool to ask, and when.

---

## Validation Results

All validation criteria from [Phase 00](phase-00-planning.md#phase-04--evidence-correlation-pfsense--suricata--hubble-ui) were met, extended to two scenarios instead of one:

- **Timeline reconstructed to second-level accuracy, consistent across sources** — confirmed for both scenarios: Scenario 4 (`pfSense filterlog` ↔ `Suricata eve.json`, matching 5-tuple and sequential IP ID between the two blocked packets), Scenario 5 (Hubble JSON at microsecond precision, confirmed by volume via Suricata's PCAP).
- **Visibility discrepancies explicitly documented, not omitted** — for both scenarios, what each source cannot see, and why, is stated directly (time precision, no alert at low volume, `eve.json` write delay, pfSense's physical absence from intra-LAN traffic, VXLAN opacity for Suricata).
- **Hubble UI service map confirms the expected traffic topology** — three screenshots (`scenario05-hubble-servicemap-*.png`) show: the blocked `attacker-pod → phase03-webserver` connection (drop verdict), the permitted `trusted-client → phase03-webserver` connection (forward verdict), and a cross-namespace view linking both sources to the same target.
- An additional synthesis (the visibility matrix), beyond the formal validation criteria, directly motivates the need for Phase 05.

---

## Problems Encountered and Resolutions

- **The original [Phase 00](phase-00-planning.md) validation criterion assumed a three-way pfSense+Suricata+Hubble correlation for Scenario 5 as well** — this turned out to be physically impossible, since cross-node traffic within a single LAN subnet never passes through pfSense. Resolved by documenting this limitation deliberately as a finding, not a gap, and extending the scope with Scenario 4 to provide material for a genuine three-way correlation involving pfSense.
- **Hubble UI showed "No data found to render a service map"** on first opening — caused by no historical buffer reaching back to the original Phase 03 test. Resolved by regenerating fresh test traffic with the UI open live.
- **The Phase 03 test pods (`attacker-pod`, `trusted-client`, `phase03-webserver`) had unexpectedly disappeared** — `kubectl get events` revealed that `k8s-worker2` had gone through a `NodeNotReady` episode roughly 23 hours earlier, triggering a `TaintManagerEviction`; bare `Pod`s (with no `Deployment`/controller) were not automatically recreated even after the node returned to `Ready`. Resolved by re-applying both manifests with `kubectl apply`; the `Service` (`LoadBalancer`) survived independently of the pods and kept the same `10.10.10.201` address, so no pfSense/Suricata configuration changes were needed.

---

## Lessons Learned Entry

The following entry was added to [`docs/lessons-learned.md`](lessons-learned.md):

**Topic: Bare `Pod`s have no resilience to transient node unavailability — even after the node returns to `Ready`, dead pods stay dead without manual intervention.**

Previously unclear: whether brief worker unavailability (for example, a momentary host resource crunch) has lasting consequences for test workloads in the cluster.

What the exercise revealed: a `NodeNotReady` episode on `k8s-worker2` (likely related to the host's limited RAM headroom, already noted in the [Phase 00 resource budget](phase-00-planning.md#resource-budget-ram)) triggered a `TaintManagerEviction` for all three test pods in this phase. The node returned to full health, but the pods themselves — created as bare `Pod`s, not a `Deployment` — were never recreated automatically, since nothing in Kubernetes itself enforces that without a controller watching for the desired state.

Takeaway: a `Deployment`/`ReplicaSet` provides self-healing after a node failure; a bare `Pod` has no such guarantee — the choice between them isn't just a manifest-style preference, it's a deliberate decision about a workload's resilience to infrastructure events, one that matters even in a test/lab environment.
