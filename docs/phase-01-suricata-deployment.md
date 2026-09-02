# Phase 01 — Suricata IDS Deployment

This phase covers standing up Suricata on a dedicated VM in pure IDS mode, with two independent, promiscuous listening interfaces implementing the pre-filter/post-filter tap architecture defined in [Phase 00](phase-00-planning.md).

---

## VM and Network Configuration

Ubuntu Server 24.04, user `adam`, two network adapters — VMware Workstation does not support VLAN tagging, so two physical adapters are used instead of one with tagged sub-interfaces:

| Interface | Network | Address | Gateway / DNS |
| --- | --- | --- | --- |
| `ens33` | VMnet11 OUTSIDE | `192.168.50.30/24` | Gateway/DNS `192.168.50.254` |
| `ens34` | VMnet10 LAN | `10.10.10.30/24` | **None** — deliberate; a passive tap has no need for an egress route |

Configured via Netplan (`/etc/netplan/50-cloud-init.yaml`).

---

## pfSense Firewall Rules

Added under a new `SURICATA` rule group on the OUTSIDE interface:

- **`Allow suricata ICMP to pfSense (diagnostics)`** — source `HOST_SURICATA_OUTSIDE`, destination This Firewall (self), ICMP. A permanent diagnostic rule.
- **`TEMP - Suricata bootstrap (apt + suricata-update)`** — source `HOST_SURICATA_OUTSIDE`, destination any, ports 80/443/53 (`PORT_INTERNET_ACCESS`). **Disabled (not deleted) once installation and the first successful `suricata-update` completed** — it remains in the ruleset as a documented, inactive artefact, to be re-enabled manually only for future ET Open updates.

Added under the existing `MGMT` group:

- **`Allow HOST_MGMT SSH to Suricata`** — destination `HOST_SURICATA_OUTSIDE`, port `PORT_SSH`, consistent with the existing rule pattern for the Kubernetes nodes.

---

## SSH Hardening

- Dedicated ED25519 key on `mgmt` (`~/.ssh/id_ed25519_suricata`), with a `Host suricata` alias in `~/.ssh/config`.
- `sshd_config`: `PermitRootLogin no`, `PasswordAuthentication no`, `KbdInteractiveAuthentication no`, `AuthenticationMethods publickey`, `AllowUsers adam@192.168.50.10`, `ListenAddress 192.168.50.30` (SSH bound exclusively to the OUTSIDE interface, unreachable from the LAN tap), `DisableForwarding yes`, `MaxAuthTries 3`.
- Verified with `sshd -t`, `sshd -T`, and `ss -ltnp` (listening only on `192.168.50.30:22`); a negative test (password login attempt) correctly returned `Permission denied (publickey)`.

---

## Suricata Installation and Configuration

Installed from the official OISF PPA (`ppa:oisf/suricata-stable`), version **8.0.6**, rather than the 7.0.3 available by default in Ubuntu universe — consistent with industry practice of not relying on a distro-packaged version for a security appliance.

**af-packet configuration** (`/etc/suricata/suricata.yaml`), two interface entries in place of the default single `eth0`:

```yaml
af-packet:
  - interface: ens33
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes

  - interface: ens34
    cluster-id: 98
    cluster-type: cluster_flow
    defrag: yes
```

Unique `cluster-id` values are required per interface so the kernel does not mix AF_PACKET load-balancing state across them. Promiscuous mode is enabled by default (`disable-promisc` left commented out).

**Operating mode:** confirmed pure IDS via the engine log `Setting engine mode to IDS mode by default`; `copy-mode` (IPS/tap) is left unset in the configuration.

**Ruleset:** `suricata-update` pulled Emerging Threats Open (`rules.emergingthreats.net`) — **68,643 rules** loaded (`/var/lib/suricata/rules/suricata.rules`), of which **52,691 active** after the default disable set was applied for unused protocols (pgsql, modbus, dnp3, enip).

---

## Validation Results

All validation criteria from [Phase 00](phase-00-planning.md#phase-01--suricata-ids-deployment) were met:

- `systemctl status suricata` → `active (running)`, no crash-loop; engine confirmed as version 8.0.6 running in `SYSTEM` mode.
- `suricata -T -c /etc/suricata/suricata.yaml -v` → configuration loads without interface errors.
- `suricatasc -c "iface-stat ens33"` → `{"pkts":13591,"invalid-checksums":0,"drop":0,"bypassed":0}`.
- `suricatasc -c "iface-stat ens34"` → `{"pkts":3756,"invalid-checksums":0,"drop":0,"bypassed":0}` — counted independently of `ens33`.
- Test traffic (a controlled ICMP ping) generated separately toward `192.168.50.30` (from `mgmt`) and `10.10.10.30` (from `k8s-master`); `eve.json` confirms events independently attributed per interface: **exactly 1 `flow` event on each interface** (`in_iface: ens33` for `192.168.50.10 → 192.168.50.30`, `in_iface: ens34` for `10.10.10.20 → 10.10.10.30`), each recording `pkts_toserver: 5` / `pkts_toclient: 5` — the full five-packet ping exchange, in both directions, captured independently on each tap.

  Earlier readings of the same counters (81/31, then 209/64) were discarded: `ens33` listens promiscuously across the entire OUTSIDE segment, so the raw, unfiltered log also captured unrelated ambient traffic (`mgmt`'s own browsing — DNS, mDNS, TLS) alongside the test traffic. The methodology was corrected by noting the `eve.json` line-count offset before the test, generating the ping, then isolating only the new lines after that offset and filtering to `proto: ICMP`. See the lessons-learned entry below for a further finding uncovered during this correction.
- `suricata-update` completed without errors; the built-in self-validation step (`Testing with suricata -T. ... Done.`) passed.
- SSH: `sshd -t` clean, `ss -ltnp` confirms listening only on `192.168.50.30:22`, password login attempt rejected (`Permission denied (publickey)`).
- Suricata confirmed **not** in inline/IPS mode via the `Setting engine mode to IDS mode by default` log line.

---

## Problems Encountered and Resolutions

- **Duplicate default route in Netplan** — both `ens33` and `ens34` initially carried a `default via ...` route, discovered on review of `ip route` before installing Suricata. Risk: unpredictable kernel choice of egress interface, with potential silent drops on the LAN segment (no pfSense rule there permits internet egress). Fixed by removing the default route from `ens34` — `ens34` is deliberately a passive tap with no egress route.
- **No response to `ping 192.168.50.254` or `ping 8.8.8.8`** despite a correct route and working ARP — initially misdiagnosed as a DNS issue. The actual cause: pfSense blocks traffic destined **to the firewall itself** by default, and ICMP was not covered by the existing internet-access rule (which only permitted ports 80/443/53). Resolved by adding the dedicated, narrow `HOST_SURICATA_OUTSIDE → This Firewall (self)` ICMP rule; a direct ICMP test to `8.8.8.8` was skipped as unnecessary — functional verification via `nslookup` and `curl` against `archive.ubuntu.com` and `rules.emergingthreats.net` confirmed the port-based rule had been working correctly from the start.
- **`af-packet: eth0: failed to find interface: No such device`** on first service start — the expected result of the default configuration pointing at `eth0`, which does not exist under Ubuntu 24.04's predictable interface naming (`ens33`/`ens34` here). Resolved by editing the `af-packet` section in `suricata.yaml`.

---

## Lessons Learned Entries

The following entries were added to [`docs/lessons-learned.md`](lessons-learned.md):

**Topic: Egress filtering for a security appliance — a deliberate choice between a narrow allowlist and "zero by default, enabled manually".**

Previously unclear: whether an IDS/IPS sensor should retain some standing, even narrowly scoped, internet access (for example, for automatic rule updates), or whether it should have no standing access at all.

What the exercise revealed: after installing Suricata and pulling ET Open once, the sensor needs no outbound traffic at all for normal operation — it works entirely passively, listening only. The temporary firewall rule used for bootstrap (apt + `suricata-update`) was deliberately **disabled, not deleted**, once installation was complete — it remains a documented, inactive artefact in the ruleset, to be enabled manually only for the duration of future rule updates.

Interview-ready explanation: *A security appliance such as an IDS sensor should default to zero standing egress paths to the internet — the less standing egress it has, the smaller its attack surface if compromised. Rather than maintaining a permanent FQDN allowlist, I keep the firewall rule disabled by default and enable it manually only for the duration of a one-off rule update, which gives an explicit, controlled time window instead of a permanent outbound channel.*

**Topic: `eve.json` logs per-flow, with a delay — not per-packet in real time.**

Previously unclear: why a simple ping test produced far more `eve.json` events than expected on a promiscuous OUTSIDE tap, and why matching a log entry's `timestamp` to when traffic actually occurred gave inconsistent results.

What the exercise revealed: two separate issues, both worth remembering for future evidence work. First, a promiscuous tap on a shared segment (`ens33` on VMnet11 OUTSIDE) captures *all* traffic on that segment, not just the traffic of interest — ambient traffic from other hosts (`mgmt`'s own DNS/TLS/browsing) will appear in the same log unless explicitly filtered out. Second, Suricata does not write an event to `eve.json` immediately per packet — it groups traffic into a "flow" and writes the event only once that flow closes or times out, which for a short ICMP exchange introduced a multi-minute gap between the actual ping and the corresponding log line.

Interview-ready explanation: *Suricata's `eve.json` is not a real-time, per-packet feed — it's largely flow-oriented, so a flow event is written only after the flow closes or times out, and its `timestamp` reflects when the record was written, not when the traffic happened. For accurate evidence or time correlation, I look at the flow's own `flow.start`/`flow.end` fields rather than the top-level `timestamp`. Separately, on a promiscuous tap covering a shared segment, I isolate the traffic of interest — by noting a log offset before the test and filtering by protocol/host afterwards — rather than assuming every logged event belongs to my test.*
