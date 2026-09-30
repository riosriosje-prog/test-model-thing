#!/usr/bin/env python3
from __future__ import annotations

import json
import urllib.parse
import urllib.request
from pathlib import Path

# H10076 historic-control listing for MORRO LIGHTHOUSE 1900, used only as
# the center of a generous 2 km discovery radius. It is NOT silently treated
# as WGS84 control for South Base.
CENTER_LAT = 18 + 28/60 + 22.774/3600
CENTER_LON = -(66 + 7/60 + 26.371/3600)
RADIUS_KM = 2.0

API = "https://geodesy.noaa.gov/api/nde/radial"
DATASHEET_URL = "https://www.ngs.noaa.gov/cgi-bin/ds_mark.prl?PidBox={pid}"
PRIORITY_PIDS = ["TV1049", "TV1020", "TV1029", "TV1030", "TV1031", "TV1021", "DE5560"]


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


def fetch_text(url: str) -> str:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "GALIA-SouthBase-NGS-Probe/0.2 (+read-only research validation)",
            "Accept": "text/plain,text/html,*/*;q=0.8",
        },
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode("utf-8", errors="replace")


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
            "center_basis": "H10076 MORRO LIGHTHOUSE 1900 historic-system coordinate; 2 km radius chosen to tolerate datum offset",
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

        datasheets = {}
        for pid in PRIORITY_PIDS:
            try:
                text_data = fetch_text(DATASHEET_URL.format(pid=pid))
                datasheets[pid] = {
                    "status": "FETCHED",
                    "url": DATASHEET_URL.format(pid=pid),
                    "contains_south_base": "SOUTH BASE" in text_data.upper(),
                    "contains_north_base": "NORTH BASE" in text_data.upper(),
                    "text": text_data[:120000],
                }
            except Exception as exc:
                datasheets[pid] = {
                    "status": "FETCH_FAILED",
                    "url": DATASHEET_URL.format(pid=pid),
                    "error": f"{type(exc).__name__}: {exc}",
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
    for pid, ds in receipt.get("priority_datasheets", {}).items():
        print("NGS_DATASHEET_STATUS=" + pid + ":" + ds.get("status", ""))
        print("NGS_DATASHEET_SOUTH_BASE=" + pid + ":" + str(ds.get("contains_south_base")))
        print("NGS_DATASHEET_NORTH_BASE=" + pid + ":" + str(ds.get("contains_north_base")))
        if ds.get("status") == "FETCHED":
            lines = ds.get("text", "").splitlines()
            keep = [
                line for line in lines
                if any(term in line.upper() for term in (
                    "PID", "DESIGNATION", "HISTORY", "RECOVERY", "STATION", "BASE",
                    "MORRO", "AZIMUTH", "REFERENCE", "MONUMENT", "STAMP", "SETTING",
                    "ESTABLISH", "189", "190", "191", "192", "193", "194"
                ))
            ]
            for line in keep[:180]:
                print("NGS_DATASHEET_LINE=" + pid + ":" + line[:1200])


if __name__ == "__main__":
    main()
