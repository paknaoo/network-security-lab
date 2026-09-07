#!/usr/bin/env bash
#
# Scenario 1 — Port Scan (SYN Scan)
#
# Simulates north-south reconnaissance from the attacker segment (OUTSIDE)
# toward the protected Kubernetes LAN, per the Phase 00 threat model
# (docs/phase-00-planning.md, Scenario A — North-South).
#
# Deliberately skips host discovery (nmap -sn): under the threat model,
# the attacker already has knowledge of the network topology, so a ping
# sweep would add an unnecessary extra footprint with no reconnaissance
# value. This script goes straight to a targeted SYN scan of five hosts
# on five Kubernetes-relevant ports.
#
# Run from the `attacker` VM (192.168.50.99).
#
# Expected result: all ports report `filtered` on all five hosts —
# pfSense silently drops attacker -> LAN traffic — while Suricata's
# custom rule (sid:9000001, local.rules) and ET Open's
# "ET SCAN Potential SSH Scan" (sid:2001219) both alert on the traffic.

set -euo pipefail

TARGETS=(
  10.10.10.20    # k8s-master
  10.10.10.21    # k8s-worker1
  10.10.10.22    # k8s-worker2
  10.10.10.200   # L2 VIP
  10.10.10.254   # pfSense LAN
)

PORTS="22,80,443,6443,10250"   # SSH, HTTP, HTTPS, Kubernetes API, kubelet

sudo nmap -sS -Pn -p "${PORTS}" -T4 "${TARGETS[@]}"
