#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import math
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

import shapefile

MORRO_HISTORIC = {"lat": 18.472992777777776, "lon": -66.12399194444444}
RADIUS_KM = 5.0
API_URL = (
    "https://geodesy.noaa.gov/api/nde/radial"
    f"?lat={MORRO_HISTORIC['lat']}&lon={MORRO_HISTORIC['lon']}"
    f"&radius={RADIUS_KM}&units=KILOMETER"
)
ARCHIVE_CANDIDATES = [
    "https://geodesy.noaa.gov/pub/DS_ARCHIVE/ShapeFiles/PR.ZIP",
    "https://www.ngs.noaa.gov/pub/DS_ARCHIVE/ShapeFiles/PR.ZIP",
    "https://nweb.ngs.noaa.gov/pub/DS_ARCHIVE/ShapeFiles/PR.ZIP",
    "https://nweb.ngs.noaa.gov/pub/DS_ARCHIVE/ShapeFiles/ARCHIVE/LAST_MONTH.20181101/PR.ZIP",
]


def fetch(url: str, timeout: int = 60) -> tuple[bytes, dict]:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "GALIA-SouthBase-GateProbe/0.2 (+read-only historical geodesy research)",
            "Accept": "application/json,application/zip,application/octet-stream,*/*;q=0.8",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        payload = resp.read()
        meta = {
            "status": getattr(resp, "status", None),
            "final_url": resp.geturl(),
            "content_type": resp.headers.get("Content-Type"),
            "content_length": resp.headers.get("Content-Length"),
        }
    return payload, meta


def haversine_km(lat1, lon1, lat2, lon2):
    r = 6371.0088
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2-lat1)
    dl = math.radians(lon2-lon1)
    a = math.sin(dp/2)**2 + math.cos(p1)*math.cos(p2)*math.sin(dl/2)**2
    return 2*r*math.asin(math.sqrt(a))


def normalize_api_rows(doc):
    if isinstance(doc, list):
        return doc
    if isinstance(doc, dict):
        for key in ("results", "data", "stations", "items"):
            if isinstance(doc.get(key), list):
                return doc[key]
    return []


def probe_api():
    result = {"url": API_URL, "status": "FETCH_FAILED"}
    try:
        payload, meta = fetch(API_URL)
        doc = json.loads(payload.decode("utf-8"))
        rows = normalize_api_rows(doc)
        result.update(meta)
        result["status"] = "FETCHED"
        result["sha256"] = hashlib.sha256(payload).hexdigest()
        result["row_count"] = len(rows)
        result["rows"] = rows
        result["name_hits"] = [
            row for row in rows
            if any(term in str(row.get("name", "")).upper() for term in ("SOUTH BASE", "MORRO"))
        ]
        dated = []
        for row in rows:
            date_val = str(row.get("settingDate") or row.get("setting_date") or "")
            if date_val and any(y in date_val for y in ("189", "190", "191")):
                dated.append(row)
        result["early_date_hits"] = dated
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


def record_to_dict(fields, rec):
    return {fields[i]: rec[i] for i in range(min(len(fields), len(rec)))}


def find_field(fields, names):
    upper = {f.upper(): f for f in fields}
    for name in names:
        if name.upper() in upper:
            return upper[name.upper()]
    for f in fields:
        fu = f.upper()
        if any(name.upper() in fu for name in names):
            return f
    return None


def probe_archive():
    attempts = []
    for url in ARCHIVE_CANDIDATES:
        attempt = {"url": url, "status": "FETCH_FAILED"}
        try:
            payload, meta = fetch(url, timeout=90)
            attempt.update(meta)
            attempt["byte_size"] = len(payload)
            attempt["sha256"] = hashlib.sha256(payload).hexdigest()
            if not zipfile.is_zipfile(Path(tempfile.mkstemp(suffix=".zip")[1])):
                pass
            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
                tmp.write(payload)
                zpath = Path(tmp.name)
            try:
                with zipfile.ZipFile(zpath) as zf:
                    attempt["zip_test"] = "PASS" if zf.testzip() is None else "FAIL"
                    attempt["members"] = zf.namelist()
                    extract_dir = Path(tempfile.mkdtemp(prefix="galia-ngs-pr-"))
                    zf.extractall(extract_dir)
                shp_paths = list(extract_dir.rglob("*.shp"))
                if not shp_paths:
                    raise RuntimeError("ZIP contains no .shp")
                shp = shp_paths[0]
                reader = shapefile.Reader(str(shp))
                fields = [f[0] for f in reader.fields[1:]]
                attempt["fields"] = fields
                name_field = find_field(fields, ["NAME", "DESIGNATION"])
                pid_field = find_field(fields, ["PID"])
                lat_field = find_field(fields, ["DEC_LAT", "LATITUDE", "LAT"])
                lon_field = find_field(fields, ["DEC_LONG", "LONGITUDE", "LON"])
                set_date_field = find_field(fields, ["SETTING_DATE", "SET_DATE", "SETTING"])
                attempt["field_map"] = {
                    "name": name_field, "pid": pid_field, "lat": lat_field,
                    "lon": lon_field, "setting_date": set_date_field,
                }
                hits = []
                nearby = []
                for rec in reader.records():
                    row = record_to_dict(fields, rec)
                    name = str(row.get(name_field, "")) if name_field else ""
                    if any(term in name.upper() for term in ("SOUTH BASE", "MORRO")):
                        hits.append(row)
                    try:
                        lat = float(row.get(lat_field)) if lat_field else None
                        lon = float(row.get(lon_field)) if lon_field else None
                        if lat is not None and lon is not None:
                            d = haversine_km(MORRO_HISTORIC["lat"], MORRO_HISTORIC["lon"], lat, lon)
                            if d <= RADIUS_KM:
                                item = dict(row)
                                item["_distance_km_from_morro_historic"] = d
                                nearby.append(item)
                    except Exception:
                        pass
                attempt["record_count"] = len(reader)
                attempt["name_hits"] = hits
                attempt["nearby_count"] = len(nearby)
                attempt["nearby"] = sorted(nearby, key=lambda x: x["_distance_km_from_morro_historic"])
                attempt["status"] = "FETCHED_AND_PARSED"
                attempts.append(attempt)
                return {"status": "FETCHED_AND_PARSED", "selected": attempt, "attempts": attempts}
            finally:
                try:
                    zpath.unlink()
                except Exception:
                    pass
        except Exception as exc:
            attempt["error"] = f"{type(exc).__name__}: {exc}"
            attempts.append(attempt)
    return {"status": "ALL_FETCHES_FAILED", "attempts": attempts}


def main():
    out = Path("south-base-gate-output")
    out.mkdir(parents=True, exist_ok=True)
    receipt = {
        "schema_version": "galia.south_base.ngs_probe.v1",
        "mode": "READ_ONLY_REMOTE_QUERY",
        "morro_historic_control": MORRO_HISTORIC,
        "radius_km": RADIUS_KM,
        "api": probe_api(),
        "archive": probe_archive(),
    }
    encoded = json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    (out / "south-base-ngs-probe.json").write_text(encoded, encoding="utf-8")

    print("SOUTH_BASE_NGS_API_STATUS=" + receipt["api"]["status"])
    print("SOUTH_BASE_NGS_API_ROWS=" + str(receipt["api"].get("row_count", 0)))
    print("SOUTH_BASE_NGS_API_NAME_HITS=" + str(len(receipt["api"].get("name_hits", []))))
    print("SOUTH_BASE_NGS_ARCHIVE_STATUS=" + receipt["archive"]["status"])
    selected = receipt["archive"].get("selected", {})
    print("SOUTH_BASE_NGS_ARCHIVE_URL=" + str(selected.get("url", "")))
    print("SOUTH_BASE_NGS_ARCHIVE_RECORDS=" + str(selected.get("record_count", 0)))
    print("SOUTH_BASE_NGS_ARCHIVE_NAME_HITS=" + str(len(selected.get("name_hits", []))))
    print("SOUTH_BASE_NGS_ARCHIVE_NEARBY=" + str(selected.get("nearby_count", 0)))
    for row in receipt["api"].get("name_hits", []):
        print("SOUTH_BASE_NGS_API_HIT=" + json.dumps(row, ensure_ascii=False, sort_keys=True))
    for row in selected.get("name_hits", []):
        print("SOUTH_BASE_NGS_ARCHIVE_HIT=" + json.dumps(row, ensure_ascii=False, sort_keys=True))
    for row in selected.get("nearby", [])[:30]:
        print("SOUTH_BASE_NGS_NEARBY=" + json.dumps(row, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
