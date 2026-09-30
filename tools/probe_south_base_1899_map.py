#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import urllib.request
from pathlib import Path

MANIFEST_URL = "https://texashistory.unt.edu/ark:/67531/metapth231585/manifest/"


def fetch(url: str, timeout: int = 60) -> tuple[bytes, str, str]:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "GALIA-SouthBase-IIIF-Probe/0.1 (+read-only historical cartography research)",
            "Accept": "application/json,image/jpeg,*/*;q=0.5",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(), r.geturl(), r.headers.get("Content-Type", "")


def iter_canvas_images(manifest: dict):
    rows = []
    # IIIF Presentation API v2
    try:
        canvases = manifest["sequences"][0]["canvases"]
        for idx, canvas in enumerate(canvases, start=1):
            resource = canvas["images"][0]["resource"]
            service = resource.get("service")
            if isinstance(service, list):
                service = service[0]
            service_id = service.get("@id") if isinstance(service, dict) else None
            rows.append({
                "canvas_index": idx,
                "label": canvas.get("label"),
                "width": canvas.get("width"),
                "height": canvas.get("height"),
                "resource_id": resource.get("@id"),
                "service_id": service_id,
            })
        return rows
    except Exception:
        pass

    # Minimal v3 fallback.
    try:
        for idx, canvas in enumerate(manifest["items"], start=1):
            body = canvas["items"][0]["items"][0]["body"]
            service = body.get("service")
            if isinstance(service, list):
                service = service[0]
            rows.append({
                "canvas_index": idx,
                "label": canvas.get("label"),
                "width": canvas.get("width"),
                "height": canvas.get("height"),
                "resource_id": body.get("id"),
                "service_id": service.get("id") if isinstance(service, dict) else None,
            })
        return rows
    except Exception:
        return []



def main() -> None:
    out = Path("research/gates/derived/south-base-1899-map")
    out.mkdir(parents=True, exist_ok=True)

    receipt = {
        "schema_version": "galia.south_base_1899_map_probe.v1",
        "mode": "READ_ONLY_REMOTE_SOURCE_RECOVERY",
        "status": "FETCH_FAILED",
        "manifest_url": MANIFEST_URL,
        "retrieval_strategy": "IIIF_PRESENTATION_MANIFEST_PLUS_DECLARED_FULL_MAX_CANVASES",
        "source_identity": {
            "title": "San Juan Harbor Porto Rico.",
            "creator": "U.S. Coast and Geodetic Survey",
            "date": "1899",
            "repository": "The Portal to Texas History / University of Texas at Arlington Library",
            "ark": "ark:/67531/metapth231585",
            "local_control_no": "2011-847",
        },
    }

    try:
        raw, final_manifest, ctype = fetch(MANIFEST_URL)
        manifest = json.loads(raw.decode("utf-8"))
        (out / "manifest.json").write_bytes(raw)
        receipt.update({
            "manifest_final_url": final_manifest,
            "manifest_content_type": ctype,
            "manifest_sha256": hashlib.sha256(raw).hexdigest(),
        })

        canvases = iter_canvas_images(manifest)
        if not canvases:
            raise RuntimeError("IIIF canvases not found")
        receipt["canvases"] = []
        for row in canvases:
            image_url = row.get("resource_id")
            if not image_url and row.get("service_id"):
                image_url = row["service_id"].rstrip("/") + "/full/max/0/default.jpg"
            if not image_url:
                continue
            image, final_image, image_type = fetch(image_url, timeout=120)
            image_path = out / f"san-juan-harbor-1899-canvas-{row['canvas_index']}-max.jpg"
            image_path.write_bytes(image)
            receipt["canvases"].append({
                **row,
                "image_request_url": image_url,
                "image_final_url": final_image,
                "image_content_type": image_type,
                "image_byte_size": len(image),
                "image_sha256": hashlib.sha256(image).hexdigest(),
                "artifact_path": str(image_path),
            })
        receipt["status"] = "FETCHED" if receipt["canvases"] else "FETCH_FAILED"
    except Exception as exc:
        receipt["status"] = "FETCH_FAILED"
        receipt["error"] = f"{type(exc).__name__}: {exc}"

    (out / "receipt.json").write_text(
        json.dumps(receipt, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print("SOUTHBASE_1899_MAP_PROBE_STATUS=" + receipt["status"])
    for row in receipt.get("canvases", []):
        print("SOUTHBASE_1899_MAP_CANVAS=" + str(row["canvas_index"]))
        print("SOUTHBASE_1899_MAP_IMAGE_URL=" + row["image_final_url"])
        print("SOUTHBASE_1899_MAP_IMAGE_BYTES=" + str(row["image_byte_size"]))
        print("SOUTHBASE_1899_MAP_IMAGE_SHA256=" + row["image_sha256"])
    if receipt.get("error"):
        print("SOUTHBASE_1899_MAP_ERROR=" + receipt["error"])
    # Remote availability is a research-source gate, not a CI infrastructure gate.
    # Preserve the receipt and do not fail the suite solely on timeout/unavailability.


if __name__ == "__main__":
    main()
