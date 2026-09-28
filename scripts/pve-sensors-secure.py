#!/usr/bin/env python3
"""Hardened launcher for Javisen/proxmox_sensors (pve-sensors-api.py).

Loads the UNMODIFIED upstream script and subclasses its Handler to add:

  1. Client IP allowlist (fail closed). Upstream has no auth and binds 0.0.0.0.
  2. Threaded server + socket timeout, so one slow SMART scan or slow client
     can't stall every other request.
  3. Cache (with a lock) for the expensive SMART scans, so polling can't
     trigger overlapping smartctl runs. /health re-scans every disk upstream.
  4. smartctl exit-status fix. smartctl's exit code is a bitmask, and non-zero
     can still come with valid JSON (bit 3 = disk failing, bit 5 = error log
     has entries, ...). Upstream drops the JSON whenever returncode != 0, so
     the disks in trouble get reported as "no SMART". This parses the JSON
     whenever it contains usable data.
  5. Query strings no longer cause 404s (/sensors?x=1).

Response formats are unchanged, so the unmodified HA integration works.

Config via environment (see pve-sensors.default):
  PVE_SENSORS_ALLOWED    comma-separated IPs/CIDRs allowed to connect (REQUIRED)
  PVE_SENSORS_BIND       address to listen on (default 0.0.0.0)
  PVE_SENSORS_PORT       default 9000
  PVE_SENSORS_CACHE_TTL  seconds to cache SMART scans (default 60)
  PVE_SENSORS_UPSTREAM   path to upstream script (default /usr/local/bin/pve-sensors-api.py)
"""
import copy
import importlib.util
import ipaddress
import json
import os
import subprocess
import sys
import threading
import time
from http.server import ThreadingHTTPServer
from urllib.parse import urlsplit

UPSTREAM = os.environ.get("PVE_SENSORS_UPSTREAM", "/usr/local/bin/pve-sensors-api.py")
BIND = os.environ.get("PVE_SENSORS_BIND", "0.0.0.0")
PORT = int(os.environ.get("PVE_SENSORS_PORT", "9000"))
CACHE_TTL = int(os.environ.get("PVE_SENSORS_CACHE_TTL", "60"))
ALLOWED_RAW = os.environ.get("PVE_SENSORS_ALLOWED", "")


def _load_upstream():
    spec = importlib.util.spec_from_file_location("pve_sensors_upstream", UPSTREAM)
    if spec is None or spec.loader is None:
        sys.exit(f"Cannot load upstream script at {UPSTREAM}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # upstream main() is behind __main__ guard
    return module


def _build_allowlist():
    nets = [ipaddress.ip_network("127.0.0.1/32")]
    try:
        if BIND not in ("0.0.0.0", ""):
            # host can query its own bind address (local curl testing)
            nets.append(ipaddress.ip_network(BIND + "/32", strict=False))
        extra = 0
        for item in ALLOWED_RAW.split(","):
            item = item.strip()
            if item:
                nets.append(ipaddress.ip_network(item, strict=False))
                extra += 1
    except ValueError as exc:
        sys.exit(f"Invalid PVE_SENSORS_ALLOWED / PVE_SENSORS_BIND value: {exc}")
    if extra == 0:
        print(
            "WARNING: PVE_SENSORS_ALLOWED is empty - only this host can connect. "
            "Set it to Home Assistant's IP.",
            file=sys.stderr,
            flush=True,
        )
    return nets


upstream = _load_upstream()
ALLOWED_NETS = _build_allowlist()

_cache = {}
_cache_lock = threading.RLock()  # re-entrant: extended scan calls fast scan
_denied_logged = set()


def _is_allowed(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in net for net in ALLOWED_NETS)


def _cached(key, fn):
    with _cache_lock:
        hit = _cache.get(key)
        if hit and (time.monotonic() - hit[0]) < CACHE_TTL:
            return copy.deepcopy(hit[1])
        value = fn()
        if not (isinstance(value, dict) and "error" in value):  # don't cache failures
            _cache[key] = (time.monotonic(), value)
        return copy.deepcopy(value)


class Handler(upstream.Handler):
    timeout = 15  # seconds; drops stalled/slow clients

    def do_GET(self):
        client_ip = self.client_address[0]
        if not _is_allowed(client_ip):
            if client_ip not in _denied_logged:  # log once per IP, no journal spam
                _denied_logged.add(client_ip)
                print(f"denied request from {client_ip}", file=sys.stderr, flush=True)
            self.send_response(403)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.path = urlsplit(self.path).path
        super().do_GET()

    # --- cached SMART scans -------------------------------------------------
    def _get_smart_data_fast(self):
        return _cached("smart_fast", lambda: upstream.Handler._get_smart_data_fast(self))

    def _get_smart_data_extended(self):
        return _cached("smart_ext", lambda: upstream.Handler._get_smart_data_extended(self))

    # --- smartctl exit-status fix ------------------------------------------
    def _get_disk_info_safe(self, device, device_type, timeout=10):
        dtype = device_type if device_type in ("scsi", "nvme") else "sat"
        try:
            result = subprocess.run(
                ["smartctl", "-a", "-d", dtype, "-j", device],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            if result.stdout.strip():
                info = json.loads(result.stdout)
                if (
                    info.get("smart_status")
                    or info.get("ata_smart_attributes")
                    or info.get("nvme_smart_health_information_log")
                    or info.get("model_name")
                ):
                    return self._parse_smart_info(info, result.returncode)
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
            pass

        # same text fallback as upstream
        try:
            result = subprocess.run(
                ["smartctl", "-i", device], capture_output=True, text=True, timeout=timeout
            )
            if result.returncode == 0:
                return self._parse_basic_info_text(result.stdout, result.returncode)
        except (subprocess.TimeoutExpired, OSError):
            pass
        return None


def main():
    server = ThreadingHTTPServer((BIND, PORT), Handler)
    server.daemon_threads = True
    print(
        f"PVE Sensors API (hardened) listening on {BIND}:{PORT}, "
        f"allowed: {', '.join(str(n) for n in ALLOWED_NETS)}",
        flush=True,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
