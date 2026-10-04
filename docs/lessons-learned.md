# Lessons Learned

This document captures per-concept takeaways as they are encountered throughout the project. Each entry follows the same structure: what was previously unclear, what the exercise revealed, and a concise takeaway.

Entries are added as the corresponding phase is completed — this file has no fixed table of contents in advance, since the concepts worth recording only become clear once the work is done.

---

---

## Egress Filtering for a Security Appliance

**Phase:** Phase 01 — Suricata IDS Deployment

**What was previously unclear:** whether an IDS/IPS sensor should retain some standing, even narrowly scoped, internet access (for example, for automatic rule updates), or whether it should have no standing access at all.

**What the exercise revealed:** after installing Suricata and pulling ET Open once, the sensor needs no outbound traffic at all for normal operation — it works entirely passively, listening only. The temporary firewall rule used for bootstrap (apt + `suricata-update`) was deliberately disabled, not deleted, once installation was complete — it remains a documented, inactive artefact in the ruleset, to be enabled manually only for the duration of future rule updates.

**Takeaway:** A security appliance such as an IDS sensor should default to zero standing egress paths to the internet — the less standing egress it has, the smaller its attack surface if compromised. Rather than maintaining a permanent FQDN allowlist, I keep the firewall rule disabled by default and enable it manually only for the duration of a one-off rule update, which gives an explicit, controlled time window instead of a permanent outbound channel.

---

## `eve.json` Logs Per-Flow, With a Delay — Not Per-Packet in Real Time

**Phase:** Phase 01 — Suricata IDS Deployment

**What was previously unclear:** why a simple ping test produced far more `eve.json` events than expected on a promiscuous OUTSIDE tap, and why matching a log entry's `timestamp` to when traffic actually occurred gave inconsistent results.

**What the exercise revealed:** two separate issues. First, a promiscuous tap on a shared segment (`ens33` on VMnet11 OUTSIDE) captures all traffic on that segment, not just the traffic of interest — ambient traffic from other hosts will appear in the same log unless explicitly filtered out. Second, Suricata does not write an event to `eve.json` immediately per packet — it groups traffic into a "flow" and writes the event only once that flow closes or times out, which for a short ICMP exchange introduced a multi-minute gap between the actual ping and the corresponding log line.

**Takeaway:** Suricata's `eve.json` is not a real-time, per-packet feed — it's largely flow-oriented, so a flow event is written only after the flow closes or times out, and its `timestamp` reflects when the record was written, not when the traffic happened. For accurate evidence or time correlation, I look at the flow's own `flow.start`/`flow.end` fields rather than the top-level `timestamp`. Separately, on a promiscuous tap covering a shared segment, I isolate the traffic of interest — by noting a log offset before the test and filtering by protocol/host afterwards — rather than assuming every logged event belongs to my test.

---

## Levels of Network Traffic Opacity for a Packet-Inspection-Based IDS

**Phase:** Phase 02 — Traffic Analysis

**What was previously unclear:** whether "the IDS can't see VXLAN traffic" and "the IDS can't see WireGuard traffic" are the same problem, and whether Hubble, as an identity-aware tool, has full visibility into everything happening in the environment.

**What the exercise revealed:** three parallel tests (plaintext ICMP, VXLAN encapsulation, WireGuard encapsulation-plus-encryption) revealed three qualitatively different levels of opacity for the same Suricata engine on the same two interfaces. Encapsulation without encryption (VXLAN) hides content only from a tool that doesn't perform explicit decapsulation — the data is there, it just has to be deliberately extracted. Encryption (WireGuard) removes that possibility entirely, regardless of tooling. Separately, Hubble — despite full, identity-aware visibility within Cilium's own scope — has an entirely different kind of limitation: it cannot see host-to-host traffic (for example, administrative SSH to the node itself), because that traffic never passes through its observation point (the eBPF datapath for pod endpoints).

**Takeaway:** Limited IDS visibility is not one phenomenon. Encapsulation hides content behind a missing decapsulation step (recoverable with extra analytical work), encryption hides it irrecoverably, and the difference in observation scope between Hubble and Suricata comes down to each tool observing a different slice of the architecture — Cilium/eBPF for pods, af-packet for physical segments.

---

## The `HOME_NET` Definition Determines the Effectiveness of the Entire Ruleset, Not Just Custom Rules

**Phase:** Phase 03 — Five Detection Scenarios (Scenario 1: Port Scan)

**What was previously unclear:** whether a broad, "safe-looking" `HOME_NET` definition (covering the entire RFC1918 private address space) is neutral to Suricata's operation, or has a real effect on detection effectiveness.

**What the exercise revealed:** with `HOME_NET` covering both the attacker segment and the protected LAN, reconnaissance traffic was classified as "internal" (`HOME_NET → HOME_NET`), which meant a significant portion of ET Open signatures built on the `$EXTERNAL_NET -> $HOME_NET` pattern could not match this traffic at all — even though the engine technically saw every packet. Narrowing `HOME_NET` to the actually protected network immediately and measurably increased detection coverage, confirmed by a custom rule and an existing ET Open signature both firing on the same test traffic.

**Takeaway:** `HOME_NET`/`EXTERNAL_NET` are not just a documentation-level declaration of topology — they are an active parameter that determines which rules can match at all. These variables need to be set to reflect the network's actual trust model, not left at their defaults.

---

## Client-Side and Intermediary Tools Can "Clean Up" Attack Traffic Before It Reaches the Network

**Phase:** Phase 03 — Five Detection Scenarios (Scenarios 2, 3 and 5)

**What was previously unclear:** whether issuing a command that contains an attack pattern (for example, `../` in a URL, a query to `.local`) guarantees that exact pattern actually appears on the wire.

**What the exercise revealed:** three separate times in this phase, an intermediary tool altered the intended payload before it was sent — `curl` normalised `../` in the URL, `systemd-resolved` intercepted `.local` locally via mDNS, and `CiliumNetworkPolicy` defaulted its selector scope to its own namespace, contrary to an intuitive reading of the rule. In each case, only direct PCAP inspection or an explicit override (`--path-as-is`, changing the TLD, an explicit namespace selector) revealed the actual behaviour.

**Takeaway:** writing and testing detection rules requires a standing habit of verifying at the raw-traffic level (PCAP, `tcpdump -A`) rather than trusting what a command was intended to do — client tools, resolvers, and policy engines have their own, sometimes non-obvious normalising or scoping behaviour that can silently invalidate a test's assumptions.

---

## Bare `Pod`s Have No Resilience to Transient Node Unavailability

**Phase:** Phase 04 — Evidence Correlation

**What was previously unclear:** whether brief worker unavailability (for example, a momentary host resource crunch) has lasting consequences for test workloads in the cluster.

**What the exercise revealed:** a `NodeNotReady` episode on `k8s-worker2` (likely related to the host's limited RAM headroom, already noted in the Phase 00 resource budget) triggered a `TaintManagerEviction` for all three test pods in this phase. The node returned to full health, but the pods themselves — created as bare `Pod`s, not a `Deployment` — were never recreated automatically, since nothing in Kubernetes itself enforces that without a controller watching for the desired state.

**Takeaway:** a `Deployment`/`ReplicaSet` provides self-healing after a node failure; a bare `Pod` has no such guarantee — the choice between them isn't just a manifest-style preference, it's a deliberate decision about a workload's resilience to infrastructure events, one that matters even in a test/lab environment.

---

## Distinguishing Signal from Noise in Logs Requires External Context, Not Just Alert Content

**Phase:** Phase 05 — Log Correlation, Manual Timeline Reconstruction

**What was previously unclear:** whether the mere presence of an alert in a log is enough to classify it as a security event, and whether diagnosing an infrastructure fault and investigating an attack can be treated as independent processes.

**What the exercise revealed:** 10 of 49 alerts in this session (the custom port-scan threshold rule) were generated not by a deliberate attack but by SYN retransmissions produced while diagnosing an unrelated infrastructure problem — distinguishing this from Event 1 (a genuine port scan) was only possible thanks to external timestamp notes, not by analysing the alert content itself. In addition, a genuine infrastructure fault (a lost L2 Announcement lease) and a genuine configuration error (a conflict between two policies) occurred close together in time, which briefly led to an incorrect causal hypothesis.

**Takeaway:** threshold rules, without additional operational context, generate false alarms for any repeating network activity, regardless of intent — an analyst has to systematically test and rule out hypotheses one at a time, rather than stopping at the first plausible one, when two independent events overlap in time.

---

## Manual Log Correlation Is Error-Prone at Higher Data Volumes

**Phase:** Phase 05 — Log Correlation, Manual Timeline Reconstruction

**What the exercise additionally revealed:** a first draft of the Phase 05 alert table contained six incorrect counts, despite a correct methodology (`grep`, manual review) — the errors came from the act of manually counting many similar, densely packed JSON lines, not from a flawed approach. Only a programmatic recount (`python3` + `Counter`) across all four evidence files revealed the discrepancies.

**Takeaway:** this is a direct, tangible demonstration of the point raised in Phase 00 about the value of correlation-automating tooling at scale — it applies not only to the volume of logs, but to the reliability of the manual analytical process itself.

---

## Threshold Rules Without Destination-Diversity Awareness Confuse One Connection's Retransmissions with a Scan

**Phase:** Phase 06 — Full Incident Investigations (Case 3: false-positive tuning)

**What was previously unclear:** why a rule intended to detect a port scan generated false positives on single, legitimate connections, and whether simply raising the threshold would suffice.

**What the exercise revealed:** the cause was not too low a threshold value, but the counting logic itself — `flow:stateless` counted a single stalled connection's SYN retransmissions as separate hits, and `track by_src` did not distinguish many targets (a scan) from one target many times (retransmissions). A genuine scan and a blocked connection looked identical to a rule that only looked at the packet count from a single source. The fix (flow context + a narrower window) eliminated the dominant source of FPs, but did not add structural destination-diversity awareness — the remaining gap (a low-and-slow scan) was named explicitly and deferred to a separate, complementary rule rather than hidden.

**Takeaway:** a threshold rule's false alarm is most often a problem of matching logic (what is counted, and in what context), not of the threshold value itself — and honest tuning names the remaining gaps rather than pretending one change solves everything.

---

## Inline/IPS Mode Is a Different Position in the Network, Not Just a Configuration Flag

**Phase:** Phase 07 — IDS → IPS Transition

**What was previously unclear:** whether moving from IDS to IPS is a configuration change (a flag/mode) or an architectural change.

**What the exercise revealed:** for six phases Suricata was a passive observer on two taps — traffic didn't pass through it, only a copy, so it couldn't block anything. IPS requires packets to actually pass through the engine (here: through the NFQUEUE queue), which places the engine on the traffic path and makes it a potential point of failure. Implementing inline operation for transit traffic would require re-architecting the topology; a narrower, isolated path (traffic directed at Suricata itself) was deliberately chosen, demonstrating the identical drop/accept mechanism without risk to the working environment. Splitting rules into `drop` (low false-positive, auto-block) and `alert` (observation) is not a syntax detail but an operational decision about what is allowed to automatically interfere with traffic.

**Takeaway:** an IDS observes a copy of traffic and can be wrong without consequences for connectivity; an IPS sits on the traffic path, and any error it makes (a false positive in `drop` mode) genuinely blocks legitimate traffic — which is why only rules with a proven, low false-positive risk qualify for `drop` mode, and the rest stay in `alert`.

---

## Pre-Filter vs. Post-Filter IDS Placement Answers Two Different Questions

**Phase:** Phase 08 — Final Validation (concept running through Phases 01–05)

**What was previously unclear:** whether sensor placement relative to the firewall is a detail or a design decision with real consequences for what evidence exists after an incident.

**What the exercise revealed:** the OUTSIDE tap (`ens33`, pre-filter) recorded every attack attempt regardless of whether pfSense blocked it — which is what let a blocked SSH attempt still be correlated against the pfSense block log. The LAN tap (`ens34`, post-filter) only ever saw what the firewall permitted, plus east-west traffic the perimeter never touches. A blocked packet never reaches the LAN segment, so a LAN-only sensor would have no record of the attempt at all.

**Takeaway:** an IDS in front of the firewall answers "what was attempted"; one behind it answers "what got through". These are different investigative questions, and which one a sensor can answer is fixed by where it sits — not something that can be tuned later in software.

---

<!--
Entry template:

## <Concept name>

**Phase:** Phase 0X — <phase name>

**What was previously unclear:** ...

**What the exercise revealed:** ...

**Takeaway:** ...
-->
