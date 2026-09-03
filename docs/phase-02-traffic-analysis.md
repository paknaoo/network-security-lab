# Phase 02 — Traffic Analysis (tcpdump, Wireshark, PCAP, L3–L7 + Hubble UI)

This phase builds practical fluency reading raw traffic (Suricata/tcpdump) and identity-aware traffic (Hubble), observing the same class of traffic from two different vantage points, and documents concrete, verified differences in visibility between the two.

---

## Test Environment

- A dedicated namespace, `phase02-traffic-test`, with two pods pinned to different workers via `nodeName` (not `nodeSelector`, for a hard placement guarantee): `phase02-server` (`nginx:alpine`) on `k8s-worker1`, `phase02-client` (`nicolaka/netshoot`) on `k8s-worker2`, connected via a ClusterIP `Service`.
- `k8s-worker2` was deliberately powered on for the duration of this test (outside the standard no-worker2 working mode from Phase 00) to force cross-node traffic over VXLAN.
- The Hubble UI SSH tunnel from `k8s-cilium-lab` Phase 04 was re-established (`ssh -L 12000:127.0.0.1:12000 master`, then `cilium hubble ui`). The dedicated `hubble` CLI (v1.19.4) was installed separately on `k8s-master`, since the installed `cilium hubble` subcommand does not include `observe` in this version — a standalone binary is required, alongside `cilium hubble port-forward` (Relay, port 4245) as a prerequisite for `hubble observe`.

---

## Three Independent Capture Scenarios

Each scenario targets a different level of visibility for the same Suricata engine, on the same two taps established in Phase 01.

### Scenario 1 — Cross-Node Pod-to-Pod Traffic (VXLAN)

`tcpdump -i ens34 udp port 8472` on Suricata, alongside `hubble observe --namespace phase02-traffic-test --follow -o json` on `k8s-master`, while `phase02-client` ran `curl` against `phase02-server` via the Service DNS name.

### Scenario 2 — Administrative Traffic, `mgmt → k8s-master` (WireGuard)

`tcpdump -i ens33 udp port 51820` on Suricata, during `ssh master 'hostname && uptime'` from `mgmt`.

### Scenario 3 — Plaintext Contrast (ICMP)

`tcpdump -i ens33 icmp` on Suricata, during `ping -c 5 192.168.50.254` from `mgmt` to pfSense.

---

## Validation Results

All validation criteria from [Phase 00](phase-00-planning.md#phase-02--traffic-analysis-tcpdump-wireshark-pcap-l3l4l7--hubble-ui) were met, with one correction to how the cross-node correlation is described (see note below), plus one extension beyond the original scope.

- **PCAP captured on `ens33` and `ens34` with correctly interpreted L3/L4/L7 layers**, confirmed across all three scenarios: L3/L4 are readable in every case (IP, UDP/ICMP); L7 is readable directly only in the plaintext scenario (the ICMP payload is fully visible in the hex dump) and only after manual decapsulation in the VXLAN scenario (`tcpdump -T vxlan` reveals the inner TCP/HTTP exchange).
- **Hubble showed the same type of traffic** — confirmed via `hubble-crossnode-flow.json`: full identity for both pods (`pod_name`, `namespace`, `labels`), a clear distinction between `trace_observation_point` values (`TO_ENDPOINT` / `TO_OVERLAY`), and IP/identity that correlate directly with the addresses seen in the decapsulated PCAP fragment (`10.244.2.198` ↔ `10.244.1.7`, port 80).

  **Correction to the original claim:** the PCAP and the Hubble capture for this scenario were not, in fact, taken in the same time window — the PCAP spans `08:57:09–08:58:20 UTC` while the Hubble JSON is timestamped `09:45:06 UTC`, a roughly 47-minute gap between two separate runs of the same reproducible test, rather than one simultaneous capture. The correlation demonstrated here is by **content** (matching pod IPs, identity, and traffic pattern — TCP handshake → HTTP GET → FIN), not by timestamp. This is a fair basis for the visibility comparison this phase is after, but it should not be read as evidence of second-level time synchronisation between the two tools — that level of correlation is the explicit goal of Phase 04, using a single, genuinely concurrent capture.
- **A concrete, verified visibility difference — established at three distinct levels, not one:**
  - On `ens34`, Suricata sees only the VXLAN/UDP 8472 envelope between **node** addresses (`10.10.10.21` ↔ `10.10.10.22`) in the cross-node scenario; the contents (TCP port 80, the HTTP exchange, pod identity) are invisible without deliberate decapsulation, which Suricata's Phase 01 default configuration does not perform automatically.
  - On `ens33`, Suricata sees only an opaque encrypted UDP/51820 stream in the WireGuard scenario — no content analysis is possible at all, a stronger limitation than VXLAN (encryption, not just encapsulation).
  - By contrast, plaintext ICMP traffic is fully readable at the byte level (hex dump), confirming that the visibility limits above come from specific transport mechanisms (encapsulation, encryption), not from a limitation of the Suricata engine itself.
- **An additional architectural finding, outside the original validation criteria but directly relevant to Phases 04–05:** Hubble has no visibility at all into the administrative SSH traffic `mgmt → k8s-master`, independent of WireGuard — because that traffic is host-to-host and never passes through Cilium's pod datapath. Hubble's limitation is therefore of a different kind than Suricata's: Hubble has no observation point at all for non-pod traffic, whereas Suricata has an observation point but lacks decapsulation/decryption within what it observes.
- **Evidence fragments stored under `snapshots/phase-02/`** — seven files: `vxlan-crossnode.pcap`, `decapsulated-http-fragment.txt`, `hubble-crossnode-flow.json`, `wireguard-encrypted.pcap`, `wireguard-opaque-traffic.txt`, `plaintext-icmp-contrast.pcap`, `plaintext-icmp-hexdump.txt`.

---

## Problems Encountered and Resolutions

- **`cilium hubble observe` does not exist** — the `cilium hubble` subcommand in the installed Cilium CLI version only includes `disable`/`enable`/`port-forward`/`ui`. Resolved by installing the standalone `hubble` CLI (v1.19.4) and running `cilium hubble port-forward` as a bridge to Relay.
- **Port 4245 already in use on a later port-forward attempt** — the result of an earlier `hubble observe` process being suspended (`Ctrl+Z` instead of `Ctrl+C`), not a problem with the port-forward itself. Resolved via `jobs`/`kill %N` on the suspended process rather than starting another, colliding port-forward.
- **`tcpdump` misidentified the encapsulation protocol** as "OTV" by default — a port-number heuristic, since port 8472 is the historical, non-IANA port for VXLAN (the standard IANA port is 4789). Resolved by explicitly forcing VXLAN decoding: `tcpdump -T vxlan`.
- **Discrepancy in the first VXLAN capture's content** — the first 20 lines of the PCAP and an initial `hubble observe --since` attempt captured ambient traffic (Cilium health checks on port 4240, DNS) instead of the intended test traffic; a subsequent attempt to query Hubble history (`--since 3h`) also returned nothing, despite the administrative traffic having occurred. Root cause: Hubble keeps a limited in-memory rolling buffer sized by event count, not by time retention — an event from roughly 22 minutes earlier had already been evicted by more recent traffic. Resolved by starting `hubble observe --follow -o json` *before* generating the test traffic, rather than querying history after the fact.
- **Ambient traffic polluting the administrative PCAP** — the first attempt to capture `mgmt → k8s-master` traffic caught 404 packets, mostly from the active SSH session to Suricata itself (the filter `host 192.168.50.10` matched all `mgmt` traffic, not only the intended destination). Resolved by narrowing the filter to `host 10.10.10.20` (the destination, not the source).
- **Zero packets despite a correctly executed SSH session to the master** — the actual cause was not the filter or timing, but topology: `ip route get 10.10.10.20` showed that all `mgmt → k8s-master` traffic is routed via `wg0` (the WireGuard full tunnel designed in `k8s-cilium-lab` Phase 06), not via the physical `ens34`. This is a deliberate architectural decision predating this repository, not a defect — Suricata could not see plaintext SSH because that traffic never exists in plaintext outside the tunnel. Resolved by reframing the test: rather than looking for non-existent plaintext SSH, the encrypted WireGuard tunnel itself was captured and documented as the correct, expected result (Scenario 2 above).
- **File transfers from `k8s-master` and `suricata` to `mgmt` were rejected outbound** — both machines have SSH deliberately restricted to connections initiated by `mgmt` (`AllowUsers`/`ListenAddress`), so an outbound `scp` from them was rejected by design. Resolved by reversing the transfer direction — `mgmt` pulls the files (`scp master:...`, `scp suricata:...`), consistent with the management-star model established in Phase 01.

---

## Lessons Learned Entry

The following entry was added to [`docs/lessons-learned.md`](lessons-learned.md):

**Topic: Levels of network traffic opacity for a packet-inspection-based IDS — encapsulation, encryption, and observation scope are not the same limitation.**

Previously unclear: whether "the IDS can't see VXLAN traffic" and "the IDS can't see WireGuard traffic" are the same problem, and whether Hubble, as an identity-aware tool, has full visibility into everything happening in the environment.

What the exercise revealed: three parallel tests (plaintext ICMP, VXLAN encapsulation, WireGuard encapsulation-plus-encryption) revealed three qualitatively different levels of opacity for the same Suricata engine on the same two interfaces. Encapsulation without encryption (VXLAN) hides content only from a tool that doesn't perform explicit decapsulation — the data is there, it just has to be deliberately extracted. Encryption (WireGuard) removes that possibility entirely, regardless of tooling. Separately, Hubble — despite full, identity-aware visibility within Cilium's own scope — has an entirely different kind of limitation: it cannot see host-to-host traffic (for example, administrative SSH to the node itself), because that traffic never passes through its observation point (the eBPF datapath for pod endpoints).

Takeaway: Limited IDS visibility is not one phenomenon. Encapsulation hides content behind a missing decapsulation step (recoverable with extra analytical work), encryption hides it irrecoverably, and the difference in observation scope between Hubble and Suricata comes down to each tool observing a different slice of the architecture — Cilium/eBPF for pods, af-packet for physical segments.
