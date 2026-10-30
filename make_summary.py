import csv, glob, os, re

HEADER = ["run_id","scenario_id","detector_enabled","scan_mode","threshold_distinct_ports",
          "window_seconds","seed_or_repetition","scan_start_time_s","scan_end_time_s",
          "scan_interval_s","start_port","end_port","target_or_targets",
          "alert_generated_yes_no","first_alert_time_s","detection_time_s",
          "max_distinct_ports_in_window","probe_count","false_positive_alert_count",
          "result_file","notes"]

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
    m = re.match(r"(fast|busy)_T(\d+)_s(\d+)$", base)
    m2 = re.match(r"stealth_I([\d.]+)_T(\d+)_s(\d+)$", base)
    if m:
        kind, T, seed = m.group(1), int(m.group(2)), int(m.group(3))
        sid = "S6" if kind == "fast" else "S5"
        mode, interval, p2 = "fast", 0.05, 100
    elif m2:
        interval, T, seed = float(m2.group(1)), int(m2.group(2)), int(m2.group(3))
        sid, mode, p2, kind = "S7", "stealth", 20, "stealth"
    else:
        continue
    v = read_scalars(path)
    first = v.get("firstFlagTime", -1)
    pb = v.get("probesBeforeFlag", -1)
    notes = []
    if kind == "busy":
        notes.append("BusyClient config")
    if "clientMaxDistinctPorts" in v:
        notes.append("clientMaxDistinctPorts=%d" % int(v["clientMaxDistinctPorts"]))
    run_id = "%s_I%g_T%d_s%d" % (sid, interval, T, seed) if sid == "S7" else "%s_T%d_s%d" % (sid, T, seed)
    rows.append([
        run_id, sid, "ON", mode, T, 5, seed, SCAN_START,
        v.get("scanEndTime", ""), interval, 1, p2, "victim[0]",
        "YES" if first != -1 else "NO",
        "" if first == -1 else first,
        "" if first == -1 else round(first - SCAN_START, 6),
        int(v.get("maxDistinctPorts", 0)),
        "" if pb == -1 else int(pb),
        int(v.get("falseFlags", 0)),
        path.replace("\\", "/"),
        "; ".join(notes),
    ])

with open("sweep_summary.csv", "w", newline="", encoding="utf-8-sig") as f:
    w = csv.writer(f)
    w.writerow(HEADER)
    w.writerows(rows)
print(len(rows), "rows written to sweep_summary.csv")
