# Lessons Learned

This document captures per-concept takeaways as they are encountered throughout the project. Each entry follows the same structure: what was previously unclear, what the exercise revealed, and a concise explanation.

Entries are added as the corresponding phase is completed — this file has no fixed table of contents in advance, since the concepts worth recording only become clear once the work is done.

---

---

## Egress Filtering for a Security Appliance

**Phase:** Phase 01 — Suricata IDS Deployment

**What was previously unclear:** whether an IDS/IPS sensor should retain some standing, even narrowly scoped, internet access (for example, for automatic rule updates), or whether it should have no standing access at all.

**What the exercise revealed:** after installing Suricata and pulling ET Open once, the sensor needs no outbound traffic at all for normal operation — it works entirely passively, listening only. The temporary firewall rule used for bootstrap (apt + `suricata-update`) was deliberately disabled, not deleted, once installation was complete — it remains a documented, inactive artefact in the ruleset, to be enabled manually only for the duration of future rule updates.

**Interview-ready explanation:** A security appliance such as an IDS sensor should default to zero standing egress paths to the internet — the less standing egress it has, the smaller its attack surface if compromised. Rather than maintaining a permanent FQDN allowlist, I keep the firewall rule disabled by default and enable it manually only for the duration of a one-off rule update, which gives an explicit, controlled time window instead of a permanent outbound channel.

---

## `eve.json` Logs Per-Flow, With a Delay — Not Per-Packet in Real Time

**Phase:** Phase 01 — Suricata IDS Deployment

**What was previously unclear:** why a simple ping test produced far more `eve.json` events than expected on a promiscuous OUTSIDE tap, and why matching a log entry's `timestamp` to when traffic actually occurred gave inconsistent results.

**What the exercise revealed:** two separate issues. First, a promiscuous tap on a shared segment (`ens33` on VMnet11 OUTSIDE) captures all traffic on that segment, not just the traffic of interest — ambient traffic from other hosts will appear in the same log unless explicitly filtered out. Second, Suricata does not write an event to `eve.json` immediately per packet — it groups traffic into a "flow" and writes the event only once that flow closes or times out, which for a short ICMP exchange introduced a multi-minute gap between the actual ping and the corresponding log line.

**Takeway:** Suricata's `eve.json` is not a real-time, per-packet feed — it's largely flow-oriented, so a flow event is written only after the flow closes or times out, and its `timestamp` reflects when the record was written, not when the traffic happened. For accurate evidence or time correlation, I look at the flow's own `flow.start`/`flow.end` fields rather than the top-level `timestamp`. Separately, on a promiscuous tap covering a shared segment, I isolate the traffic of interest — by noting a log offset before the test and filtering by protocol/host afterwards — rather than assuming every logged event belongs to my test.
---

<!--
Entry template:

## <Concept name>

**Phase:** Phase 0X — <phase name>

**What was previously unclear:** ...

**What the exercise revealed:** ...

**Interview-ready explanation:** ...
-->
