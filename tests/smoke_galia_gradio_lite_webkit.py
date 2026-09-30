#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

URL = os.environ.get("GALIA_SMOKE_URL", "http://127.0.0.1:8000/")
ARTIFACT_DIR = Path(os.environ.get("GALIA_SMOKE_ARTIFACT_DIR", "dist/smoke"))
ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)

fatal_page_errors: list[str] = []


def main() -> int:
    with sync_playwright() as p:
        browser = p.webkit.launch()
        page = browser.new_page(
            viewport={"width": 390, "height": 844},
            device_scale_factor=3,
        )
        page.on("pageerror", lambda exc: fatal_page_errors.append(str(exc)))

        try:
            page.goto(URL, wait_until="domcontentloaded", timeout=120_000)
            page.locator("gradio-lite").wait_for(state="attached", timeout=30_000)

            # These strings are rendered by app.py only after the Pyodide
            # environment has imported Gradio successfully and launched the app.
            page.get_by_text("GALIA", exact=False).first.wait_for(
                state="visible", timeout=180_000
            )
            page.get_by_text("READ ONLY", exact=False).first.wait_for(
                state="visible", timeout=30_000
            )

            body = page.locator("body").inner_text(timeout=30_000)
            forbidden = (
                "Traceback (most recent call last)",
                "unexpected keyword argument 'follow_symlinks'",
                "Can't find a pure Python 3 wheel",
                "PythonError:",
            )
            for marker in forbidden:
                if marker in body:
                    raise AssertionError(f"runtime error marker visible: {marker}")

            if fatal_page_errors:
                raise AssertionError(
                    "pageerror events observed: " + " | ".join(fatal_page_errors)
                )

            page.screenshot(
                path=str(ARTIFACT_DIR / "galia-webkit-smoke.png"),
                full_page=True,
            )
            print("GALIA_GRADIO_LITE_WEBKIT_SMOKE=PASS")
            print("GALIA_GRADIO_LITE_WEBKIT_URL=" + URL)
            return 0
        except Exception:
            page.screenshot(
                path=str(ARTIFACT_DIR / "galia-webkit-smoke-failure.png"),
                full_page=True,
            )
            print("GALIA_GRADIO_LITE_WEBKIT_SMOKE=FAIL", file=sys.stderr)
            if fatal_page_errors:
                print(
                    "PAGE_ERRORS=" + " | ".join(fatal_page_errors),
                    file=sys.stderr,
                )
            raise
        finally:
            browser.close()


if __name__ == "__main__":
    raise SystemExit(main())
