# Person B — Experiment Design: Scenario Table & Metrics

Project: Port Scanning Detection Simulation  
Environment: OMNeT++ 6.3.0 + INET 4.6.0  
Status: **Draft — confirm pending details with Person A and Person C before final runs.**

## 1. Detector rule (current team baseline)

- Distinct destination ports are counted independently for each source.
- Sliding window: 5 seconds.
- Baseline threshold: 10 distinct ports.
- Alert rule currently proposed: alert when the count becomes **greater than 10** (the 11th distinct port in the active window).
- Repeated probes to the same destination port do not increase the distinct-port count.
- Threshold sweep planned: 5, 10, 20, 40.
- Random repetitions planned: 3 seeds per experiment/configuration.

**Important:** Confirm with Person C whether the implemented detector uses `count > threshold` or `count >= threshold`, and confirm the exact window-expiry boundary before collecting final results.

## 2. Scenario table

| ID | Scenario | Detector | Traffic / behaviour | Main purpose | Expected result / success criterion | Status / notes |
|---|---|---|---|---|---|---|
| S1 | Normal traffic baseline | ON | Ordinary client traffic; exact traffic model and destination need confirmation | Check whether legitimate traffic causes false alerts | No scan alert for ordinary traffic; record any false positives | Person A's note `client (victim[0], port 80, starts at 1 s)` is ambiguous; confirm its meaning |
| S2 | Fast scan, detector OFF | OFF | Fast UDP port sweep; exact port range, target syntax, interval pending | Baseline attack behaviour without detection | Scan traffic occurs; no detector alert expected because detector is disabled | UDP is planned, pending first-test confirmation |
| S3 | Fast scan, detector ON | ON | Same fast-scan pattern as S2 | Test whether detector catches fast scanning | Alert when a source exceeds the configured distinct-port threshold within the 5 s window | Keep scan settings same as S2 for fair comparison |
| S4 | Slow / stealth scan | ON | Slow scan designed to keep distinct ports in each 5 s window at or below the threshold | Test limitation against low-rate scanning | No alert if traffic remains below the alert boundary; verify generated traffic/window count | 1 s interval is only a candidate, not confirmed |
| S5 | Busy legitimate client | ON | Higher-volume legitimate traffic; exact pattern pending | Check false positives under busy legitimate usage | No scan alert; record any false positives and traffic volume | Must not unintentionally behave like a port scan |
| S6 | Fast-scan threshold sweep | ON | Same fast-scan pattern at thresholds 5, 10, 20, 40 | Compare detection behaviour as threshold changes | Record alert/no-alert and detection time for each threshold | 3 repetitions per threshold planned; confirm OMNeT++ configuration method |
| S7 | Stealth-scan threshold sweep | ON | Same slow-scan pattern at thresholds 5, 10, 20, 40 | Compare stealth sensitivity across thresholds | Record alert/no-alert and detection time for each threshold | 3 repetitions per threshold planned; interval pending |

## 3. Metrics to collect

| Metric | Meaning / calculation | Applies to | Unit / format |
|---|---|---|---|
| Alert generated | Whether detector raised an alert for the scan source | S3, S4, S6, S7 | Yes/No |
| Detection time | First alert time minus scan start time | S3, S4, S6, S7 | seconds |
| Detection rate / True Positive Rate | Detected scan runs ÷ total scan runs | Scan scenarios | % |
| False-positive count | Alerts raised during scenarios labelled legitimate | S1, S5 | count |
| False-positive rate | Legitimate runs with an alert ÷ total legitimate runs | S1, S5 | % |
| Miss rate / False Negative Rate | Scan runs with no alert ÷ total scan runs | Scan scenarios | % |
| Distinct ports observed | Maximum distinct destination ports from one source in the active window | S2–S7 where available | count |
| Scan duration | First-to-last probe time, or agreed configured attack duration | Scan scenarios | seconds |
| Probe / packet count | Number of scan probes or relevant packets sent/observed | S2–S7 | count |
| Threshold and window | Detector settings for that run | Detector ON scenarios | threshold; seconds |
| Seed / repetition | Repetition identifier for reproducibility | Repeated runs | integer / label |
| Result file | `.sca` / `.vec` output or exported CSV filename/path | All runs | filename/path |

**Minimum for the first experiment:** scenario ID, detector ON/OFF, threshold, window, seed/repetition, alert yes/no, detection time (if alert), false-positive count (legitimate scenarios), probe count, result file, notes.

## 4. Planned threshold-sweep run matrix

| Scenario family | Thresholds | Repetitions per threshold | Planned runs |
|---|---|---:|---:|
| S6 Fast scan sweep | 5, 10, 20, 40 | 3 | 12 |
| S7 Stealth scan sweep | 5, 10, 20, 40 | 3 | 12 |

For S1–S5, confirm whether all scenarios also need 3 repetitions/seeds. Treat the run matrix as provisional until the team confirms.

## 5. Pending confirmations

- **Person A:** meaning of `client (victim[0], port 80, starts at 1 s)`.
- **Person A:** `startPort`, `endPort`, `targets` syntax, and fast/stealth `scanInterval` values.
- **Person A:** confirm UDP sweep after first test.
- **Person C:** threshold comparison (`>` or `>=`), window-boundary convention, alert output/event name, and how threshold/window are configured.
- **Person D / team:** final output metrics and agreed export format.
- **Team:** whether S1–S5 also use 3 repetitions/seeds.

## 6. Fair-comparison rules

1. Keep attack settings identical when comparing S2 (detector OFF) with S3 (detector ON).
2. Change only the threshold when comparing S6/S7 threshold values; keep scan settings and repetition plan fixed.
3. Use the same detection-time definition in every run.
4. Label legitimate and scan scenarios clearly before calculating false positives, detection rate, or miss rate.
5. Do not report performance as achieved until actual OMNeT++ runs provide evidence.
