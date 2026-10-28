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

