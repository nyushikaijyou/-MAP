#!/usr/bin/env python3
"""Offline regression/security checks for the GitHub Pages static site."""

from html.parser import HTMLParser
from pathlib import Path
import json
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "index.html"


class MarkupInspector(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.ids = set()
        self.errors = []
        self.external_scripts = []
        self.external_stylesheets = []
        self.target_blank_links = 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        element_id = a.get("id")
        if element_id:
            if element_id in self.ids:
                self.errors.append(f"Duplicate HTML id: {element_id}")
            self.ids.add(element_id)

        if tag == "script" and a.get("src", "").startswith("https://"):
            self.external_scripts.append(a)
        if tag == "link" and "stylesheet" in a.get("rel", "").split():
            if a.get("href", "").startswith("https://"):
                self.external_stylesheets.append(a)
        if tag == "a" and a.get("target", "").lower() == "_blank":
            self.target_blank_links += 1
            rel = {v.lower() for v in a.get("rel", "").split()}
            if not {"noopener", "noreferrer"}.issubset(rel):
                self.errors.append("An HTML target=_blank link lacks noopener/noreferrer")


def fail(message):
    print(f"FAIL: {message}")
    return False


def main():
    if not INDEX.is_file():
        fail("index.html was not found")
        return 1

    source = INDEX.read_text(encoding="utf-8")
    parser = MarkupInspector()
    parser.feed(source)
    parser.close()
    errors = list(parser.errors)

    required_ids = {
        "q", "city", "school", "dateFilter", "showAll", "locCount",
        "locations", "dateq", "schedule", "map", "status"
    }
    missing = sorted(required_ids - parser.ids)
    if missing:
        errors.append("Required UI element IDs missing: " + ", ".join(missing))

    # Require version-pinned Leaflet and integrity metadata for the stylesheet.
    if not re.search(r"leaflet@1\.9\.4/dist/leaflet\.css", source):
        errors.append("Pinned Leaflet CSS version not found")
    for tag in parser.external_stylesheets:
        if "leaflet" in tag.get("href", ""):
            if not tag.get("integrity") or tag.get("crossorigin", "").lower() != "anonymous":
                errors.append("Leaflet stylesheet must use SRI and crossorigin=anonymous")

    # The script loader currently adds the JS SRI attributes dynamically.
    for token in ("script.integrity=integrity", "script.crossOrigin='anonymous'",
                  "script.referrerPolicy='no-referrer'",
                  "sha256-20nQCchB9co0qIjJZRGuk2/Z9VM+kNiyxNV1lvTlZBo="):
        if token not in source:
            errors.append("Leaflet JavaScript integrity protection missing: " + token)

    if "rel=\"noopener noreferrer\"" not in source:
        errors.append("Expected safe external-link attributes not found")
    if "referrerpolicy=\"no-referrer\"" not in source:
        errors.append("Expected no-referrer policy on external map links not found")

    # Parse the embedded data as JSON and check fields used by filters and map rendering.
    match = re.search(r"const DATA = (\{.*?\});\s*\nconst \$=", source, re.S)
    if not match:
        errors.append("Could not parse embedded DATA object")
    else:
        try:
            data = json.loads(match.group(1))
            locations = data.get("locations")
            schedule = data.get("schedule")
            if not isinstance(locations, list) or not locations:
                errors.append("DATA.locations must be a non-empty array")
            if not isinstance(schedule, list) or not schedule:
                errors.append("DATA.schedule must be a non-empty array")
            for i, item in enumerate(locations or []):
                for key in ("school", "city", "name", "address"):
                    if not isinstance(item.get(key), str) or not item[key].strip():
                        errors.append(f"Location {i} has missing/invalid {key}")
                        break
                if ("lat" in item) != ("lng" in item):
                    errors.append(f"Location {i} has only one coordinate")
                if "lat" in item:
                    if not isinstance(item["lat"], (int, float)) or not -90 <= item["lat"] <= 90:
                        errors.append(f"Location {i} has invalid latitude")
                    if not isinstance(item["lng"], (int, float)) or not -180 <= item["lng"] <= 180:
                        errors.append(f"Location {i} has invalid longitude")
            for i, item in enumerate(schedule or []):
                if not re.fullmatch(r"\d{1,2}/\d{1,2}", str(item.get("date", ""))):
                    errors.append(f"Schedule entry {i} has invalid date format")
                if not isinstance(item.get("text"), str) or not item["text"].strip():
                    errors.append(f"Schedule entry {i} has missing text")
            print(f"Embedded data: {len(locations or [])} venues, {len(schedule or [])} schedule entries")
        except (json.JSONDecodeError, AttributeError, TypeError) as exc:
            errors.append(f"Embedded DATA JSON is invalid: {exc}")

    # These UI hooks are the entry points for regression-sensitive interactions.
    for token in ("function matches(x)", "function render()", "function renderSchedule()",
                  "function renderMapMarkers()", "function showVenue(x)",
                  "addEventListener('input'", "addEventListener('change'"):
        if token not in source:
            errors.append("Expected search/filter/map function or event hook missing: " + token)

    if errors:
        for item in errors:
            print("FAIL:", item)
        return 1

    print("PASS: required UI elements, Leaflet SRI, external-link safeguards, embedded data,")
    print("      coordinates, schedule formats, and key search/filter/map hooks.")
    print("Note: this is an offline static check, not a browser or live-site penetration test.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
