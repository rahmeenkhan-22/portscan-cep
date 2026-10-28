import csv, glob, os, re

HEADER = ["run_id","scenario_id","detector_enabled","scan_mode","threshold_distinct_ports",
          "window_seconds","seed_or_repetition","scan_start_time_s","scan_end_time_s",
          "scan_interval_s","start_port","end_port","target_or_targets",
          "alert_generated_yes_no","first_alert_time_s","detection_time_s",
          "max_distinct_ports_in_window","probe_count","false_positive_alert_count",
          "result_file","notes"]

SCEN = {
    "fast":    ("S6", "fast",    0.05, 1, 100),
    "stealth": ("S7", "stealth", 1.0,  1, 20),
    "busy":    ("S5", "fast",    0.05, 1, 100),
}
SCAN_START = 5.0

def read_scalars(path):
    vals = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("scalar PortScanNet.gateway.detector "):
                parts = line.split()
                vals[parts[2]] = float(parts[3])
            elif line.startswith("scalar PortScanNet.attacker.app[0] scanEndTime"):
                vals["scanEndTime"] = float(line.split()[-1])
    return vals

rows = []
for path in sorted(glob.glob("sweep/*.sca")):
    base = os.path.basename(path)[:-4]
    m = re.match(r"(fast|stealth|busy)_T(\d+)_s(\d+)$", base)
    if not m:
        continue
    kind, T, seed = m.group(1), int(m.group(2)), int(m.group(3))
    sid, mode, interval, p1, p2 = SCEN[kind]
    v = read_scalars(path)
    first = v.get("firstFlagTime", -1)
    alert = "YES" if first != -1 else "NO"
    pb = v.get("probesBeforeFlag", -1)
    rows.append([
        "%s_T%d_s%d" % (sid, T, seed), sid, "ON", mode, T, 5, seed, SCAN_START,
        v.get("scanEndTime", ""), interval, p1, p2, "victim[0]", alert,
        "" if first == -1 else first,
        "" if first == -1 else round(first - SCAN_START, 6),
        int(v.get("maxDistinctPorts", 0)),
        "" if pb == -1 else int(pb),
        int(v.get("falseFlags", 0)),
        path.replace("\\", "/"),
        "BusyClient config" if kind == "busy" else "",
    ])

with open("sweep_summary.csv", "w", newline="", encoding="utf-8-sig") as f:
    w = csv.writer(f)
    w.writerow(HEADER)
    w.writerows(rows)
print(len(rows), "rows written to sweep_summary.csv")
