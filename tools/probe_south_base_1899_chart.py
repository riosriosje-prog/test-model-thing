#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
import urllib.request
from pathlib import Path

from PIL import Image

MANIFEST = "https://texashistory.unt.edu/ark:/67531/metapth231585/manifest/"


def fetch(url: str, timeout: int = 90) -> tuple[bytes, str, str | None]:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "GALIA-SouthBase-1899-ChartProbe/0.1 (+read-only research validation)",
            "Accept": "application/json,image/jpeg,image/png,*/*;q=0.8",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(), r.geturl(), r.headers.get("Content-Type")


def walk(obj):
    if isinstance(obj, dict):
        yield obj
        for v in obj.values():
            yield from walk(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from walk(v)


def main():
    outdir = Path("artifacts/south-base-1899-chart")
    outdir.mkdir(parents=True, exist_ok=True)
    receipt = {
        "schema_version": "galia.south_base_1899_chart_probe.v1",
        "mode": "READ_ONLY",
        "manifest_url": MANIFEST,
        "status": "INIT",
    }

    raw, final_url, content_type = fetch(MANIFEST)
    manifest = json.loads(raw.decode("utf-8"))
    (outdir / "manifest.json").write_bytes(raw)
    receipt["manifest"] = {
        "final_url": final_url,
        "content_type": content_type,
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    print("UNT_MANIFEST_STATUS=PASS")
    print("UNT_MANIFEST_FINAL=" + final_url)
    print("UNT_MANIFEST_SHA256=" + receipt["manifest"]["sha256"])

    # Collect IIIF Image API service candidates robustly across IIIF Presentation 2/3.
    services = []
    direct_images = []
    for node in walk(manifest):
        typ = str(node.get("@type") or node.get("type") or "")
        ident = node.get("@id") or node.get("id")
        if isinstance(ident, str):
            if "ImageService" in typ or "imageservice" in typ.lower():
                services.append(ident.rstrip("/"))
            if re.search(r"\.(?:jpe?g|png|tiff?)(?:\?|$)", ident, re.I):
                direct_images.append(ident)
        svc = node.get("service")
        if isinstance(svc, dict):
            sid = svc.get("@id") or svc.get("id")
            if isinstance(sid, str):
                services.append(sid.rstrip("/"))
        elif isinstance(svc, list):
            for item in svc:
                if isinstance(item, dict):
                    sid = item.get("@id") or item.get("id")
                    if isinstance(sid, str):
                        services.append(sid.rstrip("/"))

    services = list(dict.fromkeys(services))
    direct_images = list(dict.fromkeys(direct_images))
    receipt["iiif_services"] = services
    receipt["direct_images"] = direct_images
    print("UNT_IIIF_SERVICES=" + json.dumps(services))
    print("UNT_DIRECT_IMAGES=" + json.dumps(direct_images[:20]))

    image_payload = None
    image_url = None
    info_payload = None
    info_url = None

    for service in services:
        try:
            info_raw, info_final, info_ct = fetch(service + "/info.json")
            info = json.loads(info_raw.decode("utf-8"))
            w = info.get("width")
            h = info.get("height")
            receipt.setdefault("service_info", []).append({
                "service": service,
                "info_url": info_final,
                "width": w,
                "height": h,
                "content_type": info_ct,
            })
            print("UNT_IIIF_INFO=" + json.dumps(receipt["service_info"][-1], sort_keys=True))
            # Request a high-resolution but bounded derivative for visual inspection.
            target_w = min(int(w or 5000), 5000)
            for suffix in (
                f"/full/{target_w},/0/default.jpg",
                f"/full/{target_w},/0/default.png",
                "/full/max/0/default.jpg",
            ):
                try:
                    payload, final_img, ct = fetch(service + suffix, 120)
                    if payload[:2] == b"\xff\xd8" or payload[:8] == b"\x89PNG\r\n\x1a\n":
                        image_payload = payload
                        image_url = final_img
                        info_payload = info_raw
                        info_url = info_final
                        break
                except Exception:
                    continue
            if image_payload:
                break
        except Exception as exc:
            receipt.setdefault("service_errors", []).append({
                "service": service,
                "error": f"{type(exc).__name__}: {exc}",
            })

    if image_payload is None:
        for url in direct_images:
            try:
                payload, final_img, ct = fetch(url, 120)
                if payload[:2] == b"\xff\xd8" or payload[:8] == b"\x89PNG\r\n\x1a\n":
                    image_payload = payload
                    image_url = final_img
                    break
            except Exception:
                continue

    if image_payload is None:
        receipt["status"] = "MANIFEST_RECOVERED_IMAGE_NOT_RECOVERED"
    else:
        ext = ".png" if image_payload[:8] == b"\x89PNG\r\n\x1a\n" else ".jpg"
        img_path = outdir / ("san-juan-harbor-1899-iiif-5000" + ext)
        img_path.write_bytes(image_payload)
        with Image.open(img_path) as im:
            receipt["image"] = {
                "url": image_url,
                "sha256": hashlib.sha256(image_payload).hexdigest(),
                "byte_size": len(image_payload),
                "width": im.width,
                "height": im.height,
                "format": im.format,
                "artifact_path": str(img_path),
            }
        receipt["status"] = "MANIFEST_AND_IMAGE_RECOVERED"
        print("UNT_CHART_IMAGE_STATUS=PASS")
        print("UNT_CHART_IMAGE_URL=" + str(image_url))
        print("UNT_CHART_IMAGE_SHA256=" + receipt["image"]["sha256"])
        print("UNT_CHART_IMAGE_DIMS=" + str(receipt["image"]["width"]) + "x" + str(receipt["image"]["height"]))

    (outdir / "receipt.json").write_text(
        json.dumps(receipt, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print("UNT_1899_CHART_PROBE_STATUS=" + receipt["status"])


if __name__ == "__main__":
    main()
