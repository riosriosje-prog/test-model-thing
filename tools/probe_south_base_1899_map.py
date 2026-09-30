#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import time
import urllib.request
from pathlib import Path

from PIL import Image

MANIFEST_URL = "https://texashistory.unt.edu/ark:/67531/metapth231585/manifest/"


def fetch_bytes(url: str, timeout: int = 90, attempts: int = 4) -> tuple[bytes, str, str]:
    last_exc = None
    for attempt in range(1, attempts + 1):
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "GALIA-SouthBase-IIIF-Probe/0.2 (+read-only historical cartography research)",
                "Accept": "application/json,image/jpeg,*/*;q=0.5",
                "Connection": "close",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                chunks = []
                while True:
                    chunk = r.read(1024 * 1024)
                    if not chunk:
                        break
                    chunks.append(chunk)
                return b"".join(chunks), r.geturl(), r.headers.get("Content-Type", "")
        except Exception as exc:
            last_exc = exc
            if attempt < attempts:
                time.sleep(attempt * 2)
    raise last_exc


def canvas_resources(manifest: dict) -> list[dict]:
    out = []
    for seq in manifest.get("sequences", []):
        for idx, canvas in enumerate(seq.get("canvases", []), 1):
            try:
                resource = canvas["images"][0]["resource"]
            except Exception:
                continue
            service = resource.get("service")
            if isinstance(service, list):
                service = service[0] if service else None
            service_id = None
            if isinstance(service, dict):
                service_id = service.get("@id") or service.get("id")
            resource_id = resource.get("@id") or resource.get("id")
            out.append({
                "index": idx,
                "label": canvas.get("label"),
                "canvas_width": canvas.get("width"),
                "canvas_height": canvas.get("height"),
                "service_id": service_id,
                "resource_id": resource_id,
            })
    return out


def main() -> None:
    out = Path("research/gates/derived/south-base-1899-map")
    out.mkdir(parents=True, exist_ok=True)

    receipt = {
        "schema_version": "galia.south_base_1899_map_probe.v2",
        "mode": "READ_ONLY_REMOTE_SOURCE_RECOVERY",
        "status": "FETCH_FAILED",
        "manifest_url": MANIFEST_URL,
        "source_identity": {
            "title": "San Juan Harbor Porto Rico.",
            "creator": "U.S. Coast and Geodetic Survey",
            "date": "1899",
            "repository": "The Portal to Texas History / University of Texas at Arlington Library",
            "ark": "ark:/67531/metapth231585",
            "local_control_no": "2011-847",
        },
        "images": [],
    }

    try:
        raw, final_manifest, ctype = fetch_bytes(MANIFEST_URL, timeout=60)
        manifest = json.loads(raw.decode("utf-8"))
        (out / "manifest.json").write_bytes(raw)
        receipt.update({
            "manifest_final_url": final_manifest,
            "manifest_content_type": ctype,
            "manifest_sha256": hashlib.sha256(raw).hexdigest(),
        })

        canvases = canvas_resources(manifest)
        receipt["canvas_count"] = len(canvases)
        if not canvases:
            raise RuntimeError("No IIIF canvas images found")

        for row in canvases:
            service = row.get("service_id")
            resource = row.get("resource_id")
            if service:
                # Respect the manifest's native max canvas dimensions. Do not over-request.
                image_url = service.rstrip("/") + "/full/max/0/default.jpg"
            elif resource:
                image_url = resource
            else:
                receipt["images"].append({**row, "status": "NO_IMAGE_RESOURCE"})
                continue

            image, final_image, image_type = fetch_bytes(image_url, timeout=120)
            image_path = out / f"san-juan-harbor-1899-canvas-{row['index']}.jpg"
            image_path.write_bytes(image)

            probe = {
                **row,
                "status": "FETCHED",
                "image_request_url": image_url,
                "image_final_url": final_image,
                "image_content_type": image_type,
                "image_byte_size": len(image),
                "image_sha256": hashlib.sha256(image).hexdigest(),
                "artifact_path": str(image_path),
            }
            try:
                with Image.open(image_path) as im:
                    probe["decoded_format"] = im.format
                    probe["decoded_width"] = im.width
                    probe["decoded_height"] = im.height
            except Exception as exc:
                probe["decode_error"] = f"{type(exc).__name__}: {exc}"
            receipt["images"].append(probe)

        fetched = [x for x in receipt["images"] if x.get("status") == "FETCHED"]
        receipt["status"] = "FETCHED" if len(fetched) == len(canvases) else "PARTIAL"
    except Exception as exc:
        receipt["status"] = "FETCH_FAILED"
        receipt["error"] = f"{type(exc).__name__}: {exc}"

    receipt_path = out / "receipt.json"
    receipt_path.write_text(
        json.dumps(receipt, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print("SOUTHBASE_1899_MAP_PROBE_STATUS=" + receipt["status"])
    print("SOUTHBASE_1899_MAP_CANVASES=" + str(receipt.get("canvas_count", 0)))
    for image in receipt.get("images", []):
        print(
            "SOUTHBASE_1899_MAP_IMAGE="
            + str(image.get("index"))
            + ":"
            + str(image.get("status"))
            + ":"
            + str(image.get("decoded_width"))
            + "x"
            + str(image.get("decoded_height"))
            + ":"
            + str(image.get("image_sha256"))
        )
    if receipt.get("error"):
        print("SOUTHBASE_1899_MAP_ERROR=" + receipt["error"])


if __name__ == "__main__":
    main()
