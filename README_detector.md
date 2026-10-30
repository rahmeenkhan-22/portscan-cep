# ScanDetector (Person C)

Port-scan detector module for the gateway. OMNeT++ 6.3.0 + INET 4.6.0. Simulation only.

## What it does
`ScanDetector` sits on the `gateway` (type `GatewayRouter`, submodule `detector`).
It watches every forwarded IPv4 packet and counts, per source IP, the number of
**distinct destination ports** seen inside a sliding time window. When that count
is strictly greater than `threshold`, the source is flagged (once per source).

## How it works
1. Registers an INET Netfilter hook (priority 0) on the gateway IPv4 module.
2. Only the FORWARD hook does work; the other hooks return ACCEPT.
3. Reads the IPv4 header, then the UDP or TCP header, without modifying the packet.
4. Ignores ICMP and any packet whose source is in `victimAddresses` (replies).
5. Per source IP keeps a queue of (time, destPort). Entries with
   `now - time >= windowSize` are removed. Distinct ports are counted.
6. If distinct > `threshold` and the source was not flagged before, it is flagged.
7. The hook always returns ACCEPT: the detector observes, it does not drop.

## Parameters (NED, set in omnetpp.ini)
| Parameter | Meaning | Default |
|---|---|---|
| `detectorEnabled` | false means the hook is not registered | `true` |
| `threshold` | flag when distinct ports > threshold | `10` |
| `windowSize` | sliding window length (needs a unit) | `5s` |
| `victimAddresses` | replies from these IPs are ignored | `10.0.0.10 10.0.0.11 10.0.0.12` |
| `attackerAddress` | used only to classify flags as true/false | `10.0.0.5` |
| `networkProtocolModule` | path to the IPv4 module | `^.ipv4.ip` |

ini keys:
```
**.gateway.detector.detectorEnabled = true
**.gateway.detector.threshold = 10
**.gateway.detector.windowSize = 5s
```

## Build
```
export PATH=$PATH:/c/Users/DELL/omnetpp-workspace/inet4.6/src
opp_makemake -f --deep -O out -KINET4_6_PROJ=<path to inet4.6> -DINET_IMPORT -I. -I'$(INET4_6_PROJ)/src' -L'$(INET4_6_PROJ)/src' -lINET'$(D)'
make MODE=debug
```
The Makefile is generated locally and is not committed. Re-run `opp_makemake`
when a new .cc file is added.

## Run
```
./out/clang-debug/portscan-cep_dbg.exe -u Cmdenv -c <Config> -n ".;<path to inet4.6>/src" omnetpp.ini
```
Configs: `General` (fast scan), `Stealth`, `BusyClient`, `Random`.
Override example: `--**.gateway.detector.threshold=5`.
For sweeps use unique `--output-scalar-file=` names, otherwise results are overwritten.


## Outputs
Scalars (module `PortScanNet.gateway.detector`), recorded in `finish()`:

| Scalar | Meaning |
|---|---|
| `firstFlagTime` | time of the first flag of the attacker; -1 if none |
| `probesBeforeFlag` | probes seen from the attacker up to and including the flagging one; -1 if none |
| `flaggedSources` | number of distinct sources flagged |
| `falseFlags` | flagged sources that are not `attackerAddress` |
| `maxDistinctPorts` | largest distinct-port count of any source in any window (global) |
| `clientMaxDistinctPorts` | largest distinct-port count of any source other than the attacker (8 in BusyClient) |

Log line per flagged source (in the run log):
`FLAGLOG,time=<s>,sourceIp=<ip>,distinctPortsSeen=<n>,probesBeforeFlag=<n>`

## Result files (detector_results/)
- `fast_T<threshold>_s<seed>` = S6 fast scan sweep
- `busy_T<threshold>_s<seed>` = S5 BusyClient (false-positive test)
- `stealth_I<interval>_T<threshold>_s<seed>` = S7 stealth sweep (interval 0.5, 1, 2 s)
- `.sca` holds the attacker and detector scalars; `.flaglog.txt` holds the FLAGLOG lines.
- `sweep_summary.csv` has one row per run (60 rows) with the exact header of `person_b_metrics_template.csv`. It has a BOM: read it with `encoding="utf-8-sig"`. Empty first_alert / detection_time / probe_count means "Not detected" (not zero).
- `make_summary.py` rebuilds the CSV from the raw `.sca` files.

## Mapping to the metrics CSV
| CSV column | Source |
|---|---|
| first_alert_time_s | firstFlagTime (empty if -1) |
| alert_generated_yes_no | YES if firstFlagTime != -1 |
| detection_time_s | firstFlagTime minus scan start (5 s) |
| probe_count | probesBeforeFlag |
| false_positive_alert_count | falseFlags |
| max_distinct_ports_in_window | maxDistinctPorts |
| notes | clientMaxDistinctPorts |

## Verified results (3 seeds each, window 5 s, scan starts at 5 s)
**S6 fast scan** (100 ports, 0.05 s, sequential): flagged at every threshold, no false flags.

| Threshold | First flag (s) | Delay (s) | Probes before flag |
|---|---|---|---|
| 5 | 5.25 | 0.25 | 6 |
| 10 | 5.50 | 0.5 | 11 |
| 20 | 6.00 | 1.0 | 21 |
| 40 | 7.00 | 2.0 | 41 |

**S5 BusyClient** (client uses 8 distinct ports): one false flag at T=5, none at T=10, 20, 40. The attacker is flagged at the same times as in S6.

**S7 stealth** (20 ports, jitter 0.5x-1.5x), maxDistinctPorts for seeds 0/1/2:

| Interval | maxDistinctPorts | T=5 | T=10 | T=20, 40 |
|---|---|---|---|---|
| 0.5 s | 10 / 10 / 12 | flagged in 3 of 3 seeds | flagged in 1 of 3 seeds (seed 2) | not detected |
| 1 s | 6 / 5 / 7 | flagged in 2 of 3 seeds | not detected | not detected |
| 2 s | 3 / 3 / 4 | not detected | not detected | not detected |

Strict `>` means exactly 10 distinct ports does not flag at T=10.

**Detector off:** no flags.

## Design decisions
- Strict `>` threshold; one flag per source; expiry rule `now - t >= windowSize`.
- Count per source IP across all victims.
- Same rule as the plain C++ prototype by Person B.
- Detection delay is measured from the scan start time (5 s).

## Limitations
- DROP of flagged sources is not implemented (future extension, agreed with Person B). The detector only observes, so network overhead is unchanged.
- `maxDistinctPorts` is one global maximum, so in BusyClient runs the attacker's value hides the client's; use `clientMaxDistinctPorts` for the client.
- Fast sequential scans have no randomness, so the 3 seeds give identical results.
- Fast scan uses 100 ports and stealth uses 20 ports: compare delay in seconds, not probe counts.
- 3 seeds is a small sample.
- Only IPv4 TCP/UDP are counted.
- `recordPcap` must be false on some setups (FCS serialization error seen with INET 4.6.0).
