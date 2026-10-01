#!/usr/bin/env python3
from __future__ import annotations

import json
import urllib.parse
import urllib.request
import zipfile
import io
import hashlib
import re
from pyproj import Geod
from pathlib import Path

# H10076 historic-control listing for MORRO LIGHTHOUSE 1900, used only as
# the center of a generous 2 km discovery radius. It is NOT silently treated
# as WGS84 control for South Base.
CENTER_LAT = 18 + 28/60 + 22.774/3600
CENTER_LON = -(66 + 7/60 + 26.371/3600)
RADIUS_KM = 3.5

API = "https://geodesy.noaa.gov/api/nde/radial"
ARCHIVE_URL = "https://geodesy.noaa.gov/pub/DS_ARCHIVE/DataSheets/PR.ZIP"
PRIORITY_PIDS = ["TV1051", "TV1049", "TV1057", "TV1020", "TV1029", "TV1030", "TV1031", "TV1021", "DE5560"]


def fetch_json(url: str):
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "GALIA-SouthBase-NGS-Probe/0.2 (+read-only research validation)",
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)



def extract_station_block(text: str, pid: str) -> str | None:
    pattern = re.compile(
        rf"(?ms)^ {re.escape(pid)} \*{{20,}}\s*$.*?(?=^ [A-Z0-9]{{6}} \*{{20,}}\s*$|\Z)"
    )
    m = pattern.search(text)
    return m.group(0) if m else None


def dms_string(degrees_value: float) -> str:
    sign = "-" if degrees_value < 0 else ""
    value = abs(degrees_value)
    d = int(value)
    m_float = (value - d) * 60.0
    m = int(m_float)
    s = (m_float - m) * 60.0
    return f"{sign}{d:02d} {m:02d} {s:08.5f}"



def main() -> None:
    params = urllib.parse.urlencode({
        "lat": f"{CENTER_LAT:.10f}",
        "lon": f"{CENTER_LON:.10f}",
        "radius": RADIUS_KM,
        "units": "KILOMETER",
    })
    url = API + "?" + params
    out = Path("research/gates/derived/south_base_ngs_radial_probe.v0_1.json")
    out.parent.mkdir(parents=True, exist_ok=True)

    receipt = {
        "schema_version": "galia.ngs_radial_probe.v1",
        "mode": "READ_ONLY_DISCOVERY_NOT_IDENTITY_PROOF",
        "query": {
            "center_lat": CENTER_LAT,
            "center_lon": CENTER_LON,
            "center_basis": "H10076 MORRO LIGHTHOUSE 1900 historic-system coordinate; 3.5 km radius chosen to tolerate datum offset and include both San Juan base stations",
            "radius_km": RADIUS_KM,
            "url": url,
        },
        "status": "FETCH_FAILED",
        "results": [],
    }

    try:
        data = fetch_json(url)
        if isinstance(data, dict):
            rows = data.get("results") or data.get("data") or data.get("stations") or []
            if not rows and "pid" in data:
                rows = [data]
        elif isinstance(data, list):
            rows = data
        else:
            rows = []

        norm = []
        for row in rows:
            norm.append({
                "pid": row.get("pid"),
                "name": row.get("name") or row.get("designation"),
                "lat": row.get("lat"),
                "lon": row.get("lon"),
                "posDatum": row.get("posDatum"),
                "posSource": row.get("posSource"),
                "posOrder": row.get("posOrder"),
                "orthoHt": row.get("orthoHt"),
                "vertDatum": row.get("vertDatum"),
            })
        receipt["results"] = norm
        receipt["result_count"] = len(norm)
        receipt["status"] = "FETCHED"

        # Discovery ranking only. Never accept identity from a fuzzy name.
        needles = ("SOUTH", "BASE", "MORRO", "LIGHT", "SAN JUAN")
        candidates = []
        for row in norm:
            name = str(row.get("name") or "").upper()
            score = sum(1 for n in needles if n in name)
            if score:
                candidates.append({**row, "name_match_score": score})
        candidates.sort(key=lambda x: (-x["name_match_score"], str(x.get("name"))))
        receipt["name_candidates"] = candidates

        by_pid = {str(row.get("pid")): row for row in norm if row.get("pid")}
        if "TV1051" in by_pid and "TV1029" in by_pid:
            sb = by_pid["TV1051"]
            lh = by_pid["TV1029"]
            geod = Geod(ellps="GRS80")
            az12, az21, distance_m = geod.inv(
                float(sb["lon"]), float(sb["lat"]),
                float(lh["lon"]), float(lh["lat"]),
            )
            historic_az = 37.0 + 9.4 / 60.0
            receipt["morro_lighthouse_bearing_diagnostic"] = {
                "from_pid": "TV1051",
                "to_pid": "TV1029",
                "ellipsoid": "GRS80",
                "current_ngs_geodesic_azimuth_deg": az12,
                "current_ngs_geodesic_azimuth_dms": dms_string(az12),
                "current_ngs_distance_m": distance_m,
                "historical_1909_true_bearing_deg": historic_az,
                "historical_1909_true_bearing_dms": "37 09 24.00000",
                "azimuth_difference_arcsec": (az12 - historic_az) * 3600.0,
                "interpretation": "Independent identity/topology diagnostic only; does not equate all lighthouse epochs or replace original survey observations.",
            }

        # Monthly NGS state archive is deterministic and much more reliable than
        # repeatedly querying the legacy CGI datasheet endpoint.
        archive_req = urllib.request.Request(
            ARCHIVE_URL,
            headers={
                "User-Agent": "GALIA-SouthBase-NGS-Probe/0.2 (+read-only research validation)",
                "Accept": "application/zip,application/octet-stream,*/*;q=0.8",
            },
        )
        with urllib.request.urlopen(archive_req, timeout=60) as r:
            archive_bytes = r.read()
        receipt["datasheet_archive"] = {
            "url": ARCHIVE_URL,
            "sha256": hashlib.sha256(archive_bytes).hexdigest(),
            "byte_size": len(archive_bytes),
        }

        datasheets = {}
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as zf:
            receipt["datasheet_archive"]["member_count"] = len(zf.infolist())
            member_names = [i.filename for i in zf.infolist()]
            receipt["datasheet_archive"]["members_sample"] = member_names[:25]

            # The archive can contain one statewide text stream or many files.
            # Search all modest-size textual members for exact PID/designation strings.
            searchable = []
            for info in zf.infolist():
                if info.is_dir() or info.file_size > 50_000_000:
                    continue
                try:
                    raw = zf.read(info)
                    text_data = raw.decode("utf-8", errors="replace")
                except Exception:
                    continue
                searchable.append((info.filename, text_data))

            corpus_upper = "\n".join(t for _, t in searchable).upper()
            receipt["archive_contains_literal_south_base"] = "SOUTH BASE" in corpus_upper
            receipt["archive_contains_literal_san_juan_north_base"] = "SAN JUAN NORTH BASE" in corpus_upper

            # Campaign-level test for the 1901 recovery initials "(JN)".
            # Search complete station blocks, not isolated lines, so the designation
            # and recovery context remain attached to each hit.
            jn_1901_blocks = []
            station_re = re.compile(
                r"(?ms)^ ([A-Z0-9]{6}) \*{20,}\s*$.*?(?=^ [A-Z0-9]{6} \*{20,}\s*$|\Z)"
            )
            for member, text_data in searchable:
                for match in station_re.finditer(text_data):
                    block = match.group(0)
                    upper = block.upper()
                    if "1901 (JN)" not in upper:
                        continue
                    pid = match.group(1)
                    designation = None
                    for line in block.splitlines():
                        if "DESIGNATION -" in line:
                            designation = line.split("DESIGNATION -", 1)[1].strip()
                            break
                    context = [
                        line.strip()
                        for line in block.splitlines()
                        if any(term in line.upper() for term in (
                            "DESIGNATION -",
                            "HISTORY",
                            "RECOVERY NOTE",
                            "1901 (JN)",
                            "TRIPOD",
                            "SCAFFOLD",
                            "STATION IS",
                            "MARKED BY",
                        ))
                    ]
                    is_recovery = bool(re.search(r"RECOVERY NOTE BY[^\n]*1901 \(JN\)", block, re.I))
                    is_description = bool(re.search(r"DESCRIBED BY[^\n]*1901 \(JN\)", block, re.I))
                    history_1901 = [
                        line.strip()
                        for line in block.splitlines()
                        if "HISTORY" in line.upper() and "1901" in line
                    ]
                    jn_1901_blocks.append({
                        "pid": pid,
                        "designation": designation,
                        "member": member,
                        "is_1901_recovery_note": is_recovery,
                        "is_1901_description": is_description,
                        "history_1901": history_1901,
                        "context_lines": context[:80],
                    })
            receipt["jn_1901_blocks"] = jn_1901_blocks
            receipt["jn_1901_block_count"] = len(jn_1901_blocks)
            receipt["jn_1901_description_count"] = sum(1 for x in jn_1901_blocks if x["is_1901_description"])
            receipt["jn_1901_recovery_note_count"] = sum(1 for x in jn_1901_blocks if x["is_1901_recovery_note"])
            receipt["jn_1901_recovery_notes"] = [x for x in jn_1901_blocks if x["is_1901_recovery_note"]]

            # Search the complete Puerto Rico archive for cross-station references
            # to South Base/TV1051 and North Base/TV1049.  This is a graph-discovery
            # aid only: a reference-object line does not itself date an observation.
            reference_hits = []
            station_re_all = re.compile(
                r"(?ms)^ ([A-Z0-9]{6}) \*{20,}\s*$.*?(?=^ [A-Z0-9]{6} \*{20,}\s*$|\Z)"
            )
            needles = ("SAN JUAN SOUTH BASE", "SOUTH BASE", "TV1051", "SAN JUAN NORTH BASE", "NORTH BASE", "TV1049")
            for member, text_data in searchable:
                for match in station_re_all.finditer(text_data):
                    pid = match.group(1)
                    block = match.group(0)
                    if pid in {"TV1051", "TV1049", "TV1057"}:
                        continue
                    upper = block.upper()
                    matched = sorted({n for n in needles if n in upper})
                    if not matched:
                        continue
                    designation = None
                    history = []
                    context = []
                    for line in block.splitlines():
                        up = line.upper()
                        if "DESIGNATION -" in line:
                            designation = line.split("DESIGNATION -", 1)[1].strip()
                        if "HISTORY" in up:
                            history.append(line.strip())
                        if any(n in up for n in needles):
                            context.append(line.strip())
                    reference_hits.append({
                        "source_pid": pid,
                        "source_designation": designation,
                        "member": member,
                        "matched_terms": matched,
                        "history_lines": history[:40],
                        "reference_context": context[:80],
                    })
            receipt["base_station_reference_hits"] = reference_hits
            receipt["base_station_reference_hit_count"] = len(reference_hits)

            for pid in PRIORITY_PIDS:
                hits = []
                for member, text_data in searchable:
                    block = extract_station_block(text_data, pid)
                    if block:
                        hits.append({
                            "member": member,
                            "contains_south_base": "SOUTH BASE" in block.upper(),
                            "contains_north_base": "NORTH BASE" in block.upper(),
                            "text": block,
                        })
                datasheets[pid] = {
                    "status": "FOUND_IN_ARCHIVE" if hits else "NOT_FOUND_IN_ARCHIVE",
                    "hits": hits,
                }
        receipt["priority_datasheets"] = datasheets
    except Exception as exc:
        receipt["error"] = f"{type(exc).__name__}: {exc}"

    out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("SOUTH_BASE_NGS_PROBE_STATUS=" + receipt["status"])
    print("SOUTH_BASE_NGS_RESULT_COUNT=" + str(receipt.get("result_count", 0)))
    for row in receipt.get("results", []):
        print("NGS_ROW=" + json.dumps(row, sort_keys=True))
    for row in receipt.get("name_candidates", []):
        print("NGS_NAME_CANDIDATE=" + json.dumps(row, sort_keys=True))
    if receipt.get("morro_lighthouse_bearing_diagnostic"):
        print("SOUTH_BASE_MORRO_BEARING_DIAGNOSTIC=" + json.dumps(
            receipt["morro_lighthouse_bearing_diagnostic"], sort_keys=True
        ))
    archive = receipt.get("datasheet_archive", {})
    if archive:
        print("NGS_PR_ARCHIVE_SHA256=" + archive.get("sha256", ""))
        print("NGS_PR_ARCHIVE_BYTES=" + str(archive.get("byte_size", 0)))
        print("NGS_PR_ARCHIVE_MEMBERS=" + str(archive.get("member_count", 0)))
        print("NGS_PR_ARCHIVE_LITERAL_SOUTH_BASE=" + str(receipt.get("archive_contains_literal_south_base")))
        print("NGS_PR_ARCHIVE_LITERAL_SAN_JUAN_NORTH_BASE=" + str(receipt.get("archive_contains_literal_san_juan_north_base")))
    print("NGS_BASE_REFERENCE_HIT_COUNT=" + str(receipt.get("base_station_reference_hit_count", 0)))
    for row in receipt.get("base_station_reference_hits", []):
        print("NGS_BASE_REFERENCE_HIT=" + json.dumps(row, sort_keys=True))
    print("NGS_1901_JN_BLOCK_COUNT=" + str(receipt.get("jn_1901_block_count", 0)))
    print("NGS_1901_JN_DESCRIPTION_COUNT=" + str(receipt.get("jn_1901_description_count", 0)))
    print("NGS_1901_JN_RECOVERY_NOTE_COUNT=" + str(receipt.get("jn_1901_recovery_note_count", 0)))
    for row in receipt.get("jn_1901_blocks", []):
        print("NGS_1901_JN_BLOCK=" + json.dumps(row, sort_keys=True))
    for row in receipt.get("jn_1901_recovery_notes", []):
        print("NGS_1901_JN_RECOVERY_NOTE=" + json.dumps(row, sort_keys=True))

    for pid, ds in receipt.get("priority_datasheets", {}).items():
        print("NGS_DATASHEET_STATUS=" + pid + ":" + ds.get("status", ""))
        for hit in ds.get("hits", []):
            print("NGS_DATASHEET_MEMBER=" + pid + ":" + hit.get("member", ""))
            print("NGS_DATASHEET_SOUTH_BASE=" + pid + ":" + str(hit.get("contains_south_base")))
            print("NGS_DATASHEET_NORTH_BASE=" + pid + ":" + str(hit.get("contains_north_base")))
            lines = hit.get("text", "").splitlines()
            keep = [
                line for line in lines
                if any(term in line.upper() for term in (
                    "PID", "DESIGNATION", "HISTORY", "RECOVERY", "STATION", "BASE",
                    "MORRO", "AZIMUTH", "REFERENCE", "MONUMENT", "STAMP", "SETTING",
                    "ESTABLISH", "189", "190", "191", "192", "193", "194"
                ))
            ]
            for line in keep[:240]:
                print("NGS_DATASHEET_LINE=" + pid + ":" + line[:1200])
            if pid in {"TV1051", "TV1049"}:
                for line in lines:
                    if line.lstrip().startswith(pid):
                        print("NGS_FULL_STATION_LINE=" + pid + ":" + line[:1600])


if __name__ == "__main__":
    main()
