import csv
import glob
import os
import re
import shutil

SOURCE = "detector_results/sweep_summary.csv"
OUTPUT = "detector_results/sweep_summary.preview.csv"

HEADER = [
    "run_id", "scenario_id", "detector_enabled", "scan_mode",
    "threshold_distinct_ports", "window_seconds",
    "seed_or_repetition", "scan_start_time_s", "scan_end_time_s",
    "scan_interval_s", "start_port", "end_port", "target_or_targets",
    "alert_generated_yes_no", "first_alert_time_s", "detection_time_s",
    "max_distinct_ports_in_window", "probe_count",
    "false_positive_alert_count", "result_file", "notes"
]

def read_scalars(path):
    vals = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("scalar PortScanNet.gateway.detector "):
                parts = line.split()
                vals[parts[2]] = float(parts[3])

            elif line.startswith("scalar PortScanNet.attacker.app[0] "):
                parts = line.split()
                if len(parts) >= 4:
                    if parts[2] in ("scanEndTime", "probesSent"):
                        vals[parts[2]] = float(parts[3])

    return vals


if not os.path.exists(SOURCE):
    raise FileNotFoundError(SOURCE)

with open(SOURCE, newline="", encoding="utf-8-sig") as f:
    reader = csv.reader(f)
    existing_header = next(reader)
    existing_rows = list(reader)

if existing_header != HEADER:
    raise ValueError("Existing CSV header does not match expected header")

existing_ids = {row[0] for row in existing_rows}

new_rows = []

for path in sorted(glob.glob("sweep/*.sca")):
    base = os.path.basename(path)[:-4]

    m2 = re.fullmatch(r"off_fast_s(\d+)", base)
    m1 = re.fullmatch(r"normal_T10_s(\d+)", base)

    if m2:
        seed = int(m2.group(1))
        sid = "S2"
        run_id = f"S2_T10_s{seed}"

        if run_id in existing_ids:
            continue

        v = read_scalars(path)
        first = v.get("firstFlagTime", -1)

        row = [
            run_id, sid, "OFF", "fast",
            10, 5, seed, 5.0,
            v.get("scanEndTime", ""),
            0.05, 1, 100, "victim[0]",
            "YES" if first != -1 else "NO",
            "" if first == -1 else first,
            "" if first == -1 else round(first - 5.0, 6),
            int(v.get("maxDistinctPorts", 0)),
            "" if v.get("probesBeforeFlag", -1) == -1
                 else int(v["probesBeforeFlag"]),
            int(v.get("falseFlags", 0)),
            path.replace("\\", "/"),
            "Detector disabled; attackerProbesSent=%d; clientMaxDistinctPorts=%d"
            % (int(v.get("probesSent", 0)),
               int(v.get("clientMaxDistinctPorts", 0)))
        ]

    elif m1:
        seed = int(m1.group(1))
        sid = "S1"
        run_id = f"S1_T10_s{seed}"

        if run_id in existing_ids:
            continue

        v = read_scalars(path)
        first = v.get("firstFlagTime", -1)

        row = [
            run_id, sid, "ON", "normal",
            10, 5, seed, "", "", "", "", "", "",
            "YES" if first != -1 else "NO",
            "" if first == -1 else first,
            "" if first == -1 else round(first - 5.0, 6),
            int(v.get("maxDistinctPorts", 0)),
            "",
            int(v.get("falseFlags", 0)),
            path.replace("\\", "/"),
            "Normal client traffic only; attackerProbesSent=%d; clientMaxDistinctPorts=%d"
            % (int(v.get("probesSent", 0)),
               int(v.get("clientMaxDistinctPorts", 0)))
        ]

    else:
        continue

    new_rows.append(row)
    existing_ids.add(run_id)

if len(new_rows) != 6:
    raise ValueError(
        f"Expected 6 new S1/S2 rows, found {len(new_rows)}. "
        "Original CSV has not been changed."
    )

shutil.copyfile(SOURCE, OUTPUT)

with open(OUTPUT, "a", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerows(new_rows)

print("Preview created:", OUTPUT)
print("Existing rows preserved:", len(existing_rows))
print("New rows added:", len(new_rows))
print("Total data rows:", len(existing_rows) + len(new_rows))
