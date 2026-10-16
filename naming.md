# Naming Sheet: Port Scanning Detection Simulation

Versions: OMNeT++ 6.3.0, INET 4.6.0
Package: portscan
Network: PortScanNet
Rule: use these names exactly. Ask Person A before changing anything.

## Nodes
attacker, client, gateway, switch, victim[0..2], configurator

## Victims (Person A)
Server app: TcpGenericServerApp on every victim
Open (listening) ports: 80, 443, 22

## Normal client (Person A)
App: TcpBasicClientApp, sends requests to victim[0] port 80
Starts at 1s. Used for scenario (a) and as the base for scenario (e).

## Attacker module: PortScanner (Person A)
Probe type: UDP first (TCP connect scan is an optional upgrade)
Parameters:
  startPort     first port to probe
  endPort       last port to probe
  scanInterval  time between probes, in seconds (small = fast scan, large = stealth)
  scanMode      "sequential" | "random" | "stealth"
  targets       (proposed) which victim(s) to scan, e.g. "victim[0]"
  startTime     (proposed) when the scan begins, in seconds

## Detector module: ScanDetector, on gateway (Person C)
Parameters:
  detectorEnabled   true / false
  threshold         number of distinct destination ports from one source that triggers a flag
  windowSize        sliding window length, in seconds

## Metrics (recorded with recordScalar, Person C records, Person D reads)
  firstFlagTime     (proposed) simulation time in seconds of the first flag; -1 if nothing was flagged
  probesBeforeFlag  number of attacker probes that got through before the first flag
  flaggedSources    number of distinct sources flagged (the list of IPs goes in the log)
  falseFlags        number of flagged sources that are NOT the attacker
Definitions above are a draft: Person B (success criteria) and Person C confirm.

## Scenarios and configs (Person B)
Config section names: to be added by Person B (one per scenario a to e)

## Results format (Person D)
CSV column names: to be agreed with Person D after the first result export