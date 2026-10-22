# Naming Sheet: Port Scanning Detection Simulation

Versions: OMNeT++ 6.3.0, INET 4.6.0
Package: portscan
Network: PortScanNet
Repo: <PASTE GITHUB LINK HERE>
Rule: use these names exactly. Ask Person A before changing anything.

## Nodes
attacker, client, gateway, switch, victim[0..2], configurator

## Victims (Person A)
Server app: TcpGenericServerApp on every victim
Open (listening) TCP ports: 80, 443, 22

## Normal client (Person A)
App: TcpBasicClientApp, sends requests to victim[0] port 80
Starts at 1s. Used for scenario (a) and as the base for scenario (e).

## Attacker module: PortScanner (Person A) - IMPLEMENTED
Files: PortScanner.ned, PortScanner.h, PortScanner.cc (extends INET's UdpBasicApp)
Instance: attacker.app[0].typename = "PortScanner"
Probe type: UDP sweep, one UDP packet per port. Confirmed in a test run (100 ports,
  scanInterval 0.05 s): all 100 probes reached victim[0] and were dropped as "no port
  found"; replies returned to the attacker (inferred from frame sizes, ICMP
  port-unreachable).
  A TCP connect scan is an optional upgrade.
Parameters:
  startPort     first port to probe (default 1)
  endPort       last port to probe (default 1024)
  scanInterval  time between probes, in seconds (small = fast scan, large = stealth)
  scanMode      "sequential" | "random" | "stealth"
  destAddresses target host, e.g. "victim[0]" (inherited from UdpBasicApp).
                Use one target for now.
  startTime     when the scan begins, in seconds (inherited from UdpBasicApp)
Scan modes:
  sequential    ports in ascending order, fixed scanInterval
  random        ports in shuffled order, fixed scanInterval
  stealth       ports in shuffled order, each gap jittered to 0.5x - 1.5x of
                scanInterval (set scanInterval high for a real stealth run)
Random order and jitter use OMNeT++'s own RNG, so seeds control them.
Scalars recorded by the attacker: probesSent, scanEndTime
Example config:
  **.attacker.numApps = 1
  **.attacker.app[0].typename = "PortScanner"
  **.attacker.app[0].destAddresses = "victim[0]"
  **.attacker.app[0].startTime = 5s
  **.attacker.app[0].startPort = 1
  **.attacker.app[0].endPort = 100
  **.attacker.app[0].scanInterval = 0.05s
  **.attacker.app[0].scanMode = "sequential"

## Detector module: ScanDetector, on gateway (Person C)
Placement (proposed): gateway becomes GatewayRouter (extends Router) with a
  detector: ScanDetector submodule. Person C confirms how it hooks into packets.
Rule: count distinct destination ports per source IP, for both TCP and UDP.
Parameters:
  detectorEnabled   true / false
  threshold         number of distinct destination ports from one source that triggers a flag
  windowSize        sliding window length, in seconds

## Metrics (recorded with recordScalar, Person C records, Person D reads)
  firstFlagTime     (proposed) simulation time in seconds of the first flag; -1 if nothing was flagged
  probesBeforeFlag  number of attacker probes that got through before the first flag
                    (counted at the gateway: probe packets seen before the first flag)
  flaggedSources    number of distinct sources flagged (the list of IPs goes in the log)
  falseFlags        number of flagged sources that are NOT the attacker
Definitions above are a draft: Person B (success criteria) and Person C confirm.

## Random seeds
repeat = N in omnetpp.ini gives each repetition a different seed.
Seed counts and sweep values are decided by Person B.

## Scenarios and configs (Person B)
Config section names: to be added by Person B (one per scenario a to e)

## Results format (Person D)
CSV column names: to be agreed with Person D after the first result export
