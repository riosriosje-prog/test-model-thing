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


def find_image_service(manifest: dict) -> str | None:
    # IIIF Presentation API v2
    try:
        resource = manifest["sequences"][0]["canvases"][0]["images"][0]["resource"]
        service = resource.get("service")
        if isinstance(service, list):
            service = service[0]
        if isinstance(service, dict):
            return service.get("@id") or service.get("id")
        if resource.get("@id"):
            # direct image resource fallback
            return resource["@id"]
    except Exception:
        pass

    # IIIF Presentation API v3
    try:
        body = manifest["items"][0]["items"][0]["items"][0]["body"]
        service = body.get("service")
        if isinstance(service, list):
            service = service[0]
        if isinstance(service, dict):
            return service.get("id") or service.get("@id")
        return body.get("id")
    except Exception:
        return None


def main() -> None:
    out = Path("research/gates/derived/south-base-1899-map")
    out.mkdir(parents=True, exist_ok=True)

    raw, final_manifest, ctype = fetch(MANIFEST_URL)
    manifest = json.loads(raw.decode("utf-8"))
    (out / "manifest.json").write_bytes(raw)

    service = find_image_service(manifest)
    if not service:
        raise SystemExit("IIIF image service/resource not found")

    if service.lower().endswith((".jpg", ".jpeg", ".png")):
        image_url = service
    else:
        image_url = service.rstrip("/") + "/full/4000,/0/default.jpg"

    image, final_image, image_type = fetch(image_url, timeout=120)
    image_path = out / "san-juan-harbor-1899-iiif-4000.jpg"
    image_path.write_bytes(image)

    receipt = {
        "schema_version": "galia.south_base_1899_map_probe.v1",
        "mode": "READ_ONLY_REMOTE_SOURCE_RECOVERY",
        "manifest_url": MANIFEST_URL,
        "manifest_final_url": final_manifest,
        "manifest_content_type": ctype,
        "manifest_sha256": hashlib.sha256(raw).hexdigest(),
        "iiif_service": service,
        "image_request_url": image_url,
        "image_final_url": final_image,
        "image_content_type": image_type,
        "image_byte_size": len(image),
        "image_sha256": hashlib.sha256(image).hexdigest(),
        "source_identity": {
            "title": "San Juan Harbor Porto Rico.",
            "creator": "U.S. Coast and Geodetic Survey",
            "date": "1899",
            "repository": "The Portal to Texas History / University of Texas at Arlington Library",
            "ark": "ark:/67531/metapth231585",
            "local_control_no": "2011-847",
        },
    }
    (out / "receipt.json").write_text(
        json.dumps(receipt, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print("SOUTHBASE_1899_MAP_PROBE=PASS")
    print("SOUTHBASE_1899_MAP_IIIF_SERVICE=" + service)
    print("SOUTHBASE_1899_MAP_IMAGE_URL=" + final_image)
    print("SOUTHBASE_1899_MAP_IMAGE_BYTES=" + str(len(image)))
    print("SOUTHBASE_1899_MAP_IMAGE_SHA256=" + receipt["image_sha256"])


if __name__ == "__main__":
    main()
