#!/usr/bin/env python3
from __future__ import annotations

import io
import json
import urllib.request
import zipfile
from pathlib import Path

import shapefile

CANDIDATES = [
    "https://geodesy.noaa.gov/pub/DS_ARCHIVE/ShapeFiles/PR.zip",
    "https://geodesy.noaa.gov/pub/DS_ARCHIVE/Shapefiles/PR.zip",
    "https://www.ngs.noaa.gov/pub/DS_ARCHIVE/ShapeFiles/PR.zip",
    "https://www.ngs.noaa.gov/pub/DS_ARCHIVE/Shapefiles/PR.zip",
]
ARCHIVE_PAGE = "https://geodesy.noaa.gov/cgi-bin/sf_archive.prl"


def fetch(url: str, timeout: int = 60):
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "GALIA-SouthBase-NGS-Probe/0.1 (+read-only research validation)",
            "Accept": "*/*",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.geturl(), r.headers, r.read()


def main():
    receipt = {
        "schema_version": "galia.south_base_ngs_archive_probe.v1",
        "mode": "READ_ONLY",
        "archive_page": {},
        "candidate_urls": [],
        "matches": [],
    }

    try:
        status, final_url, headers, body = fetch(ARCHIVE_PAGE, 45)
        receipt["archive_page"] = {
            "status": status,
            "final_url": final_url,
            "content_type": headers.get("Content-Type"),
            "body_prefix": body[:12000].decode("utf-8", errors="replace"),
        }
        print("NGS_ARCHIVE_PAGE_STATUS=" + str(status))
        print("NGS_ARCHIVE_PAGE_FINAL=" + final_url)
        print("NGS_ARCHIVE_PAGE_PREFIX=" + receipt["archive_page"]["body_prefix"][:8000].replace("\n"," "))
    except Exception as exc:
        receipt["archive_page"] = {"error": f"{type(exc).__name__}: {exc}"}
        print("NGS_ARCHIVE_PAGE_ERROR=" + receipt["archive_page"]["error"])

    payload = None
    source_url = None
    for url in CANDIDATES:
        row = {"url": url}
        try:
            status, final_url, headers, body = fetch(url, 90)
            row.update({
                "status": status,
                "final_url": final_url,
                "content_type": headers.get("Content-Type"),
                "byte_size": len(body),
                "zip_magic": body[:4].hex(),
            })
            print("NGS_CANDIDATE=" + json.dumps(row, sort_keys=True))
            if body.startswith(b"PK\x03\x04"):
                payload = body
                source_url = final_url
                receipt["candidate_urls"].append(row)
                break
        except Exception as exc:
            row["error"] = f"{type(exc).__name__}: {exc}"
            print("NGS_CANDIDATE=" + json.dumps(row, sort_keys=True))
        receipt["candidate_urls"].append(row)

    if not payload:
        receipt["status"] = "ARCHIVE_ZIP_NOT_RECOVERED"
    else:
        receipt["status"] = "ARCHIVE_ZIP_RECOVERED"
        receipt["source_url"] = source_url
        z = zipfile.ZipFile(io.BytesIO(payload))
        names = z.namelist()
        receipt["members"] = names
        print("NGS_ZIP_MEMBERS=" + json.dumps(names))

        shp_name = next((n for n in names if n.lower().endswith(".shp")), None)
        shx_name = next((n for n in names if n.lower().endswith(".shx")), None)
        dbf_name = next((n for n in names if n.lower().endswith(".dbf")), None)
        if shp_name and shx_name and dbf_name:
            sf = shapefile.Reader(
                shp=io.BytesIO(z.read(shp_name)),
                shx=io.BytesIO(z.read(shx_name)),
                dbf=io.BytesIO(z.read(dbf_name)),
                encoding="latin1",
            )
            fields = [f[0] for f in sf.fields[1:]]
            receipt["fields"] = fields
            print("NGS_FIELDS=" + json.dumps(fields))
            upper_fields = {f.upper(): i for i, f in enumerate(fields)}
            name_idx = upper_fields.get("NAME")
            pid_idx = upper_fields.get("PID")
            first_idx = upper_fields.get("FIRST_RECV")
            last_idx = upper_fields.get("LAST_RECV")
            state_idx = upper_fields.get("STATE")
            county_idx = upper_fields.get("COUNTY")
            lat_idx = next((upper_fields[k] for k in ("LATITUDE","LAT","NAD83_LAT") if k in upper_fields), None)
            lon_idx = next((upper_fields[k] for k in ("LONGITUDE","LON","NAD83_LON") if k in upper_fields), None)

            for sr in sf.iterShapeRecords():
                vals = list(sr.record)
                name = str(vals[name_idx]) if name_idx is not None else ""
                name_u = name.upper()
                if any(token in name_u for token in ("SOUTH BASE","MORRO","SAN JUAN")):
                    record_map = {fields[i]: vals[i] for i in range(len(fields))}
                    row = {
                        "name": name,
                        "pid": vals[pid_idx] if pid_idx is not None else None,
                        "first_recv": vals[first_idx] if first_idx is not None else None,
                        "last_recv": vals[last_idx] if last_idx is not None else None,
                        "state": vals[state_idx] if state_idx is not None else None,
                        "county": vals[county_idx] if county_idx is not None else None,
                        "shape_xy": list(sr.shape.points[0]) if sr.shape.points else None,
                        "record": record_map,
                    }
                    if lat_idx is not None:
                        row["latitude_field"] = vals[lat_idx]
                    if lon_idx is not None:
                        row["longitude_field"] = vals[lon_idx]
                    receipt["matches"].append(row)
                    print("NGS_MATCH=" + json.dumps(row, default=str, sort_keys=True))
        else:
            receipt["status"] = "ZIP_RECOVERED_BUT_SHAPEFILE_INCOMPLETE"

    south = next((x for x in receipt.get("matches", []) if x.get("pid") == "TV1051"), None)
    if south:
        for ds_url in [
            "https://geodesy.noaa.gov/cgi-bin/ds_mark.prl?PidBox=TV1051",
            "https://www.ngs.noaa.gov/cgi-bin/ds_mark.prl?PidBox=TV1051",
        ]:
            try:
                status, final_url, headers, body = fetch(ds_url, 60)
                text_body = body.decode("latin1", errors="replace")
                receipt["tv1051_datasheet"] = {
                    "status": status,
                    "url": final_url,
                    "content_type": headers.get("Content-Type"),
                    "body": text_body,
                }
                print("TV1051_DATASHEET_STATUS=" + str(status))
                print("TV1051_DATASHEET_URL=" + final_url)
                print("TV1051_DATASHEET_BEGIN")
                print(text_body[:50000])
                print("TV1051_DATASHEET_END")
                break
            except Exception as exc:
                print("TV1051_DATASHEET_ERROR=" + f"{type(exc).__name__}: {exc}")

    out = Path("artifacts/south-base-ngs-archive-probe.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(receipt, indent=2, ensure_ascii=False, default=str) + "\n", encoding="utf-8")
    print("SOUTH_BASE_NGS_PROBE_STATUS=" + receipt["status"])
    print("SOUTH_BASE_NGS_MATCH_COUNT=" + str(len(receipt.get("matches", []))))


if __name__ == "__main__":
    main()
