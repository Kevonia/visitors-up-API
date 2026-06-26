"""Gate hardware drivers — turn an "open gate" intent into a physical pulse.

Pattern A (API-mediated): the security app calls the backend, the backend calls
the gate's relay. Each driver is a small function that takes a Gate's config and
returns (ok, detail). New hardware = a new branch here, nothing else changes.

Drivers:
  MANUAL  no hardware — always "succeeds"; the guard opens by hand, we just audit.
  HTTP    pulse a relay over HTTP (Shelly / Tasmota / Home-Assistant / any webhook).
  GSM     trigger a GSM/SIM relay through an HTTP→SMS gateway (config-driven).

Config (JSON on the Gate, encrypted at rest) by driver:
  HTTP: {"url": "...", "method": "GET|POST", "headers": {..}, "body": "..",
         "verify_tls": true, "timeout": 6}
  GSM:  {"gateway_url": "...", "method": "GET|POST", "headers": {..}, "body": ".."}
        e.g. an HTTP-SMS gateway that texts the SIM relay "open".
"""
from __future__ import annotations

from typing import Tuple

import requests

from ..enums import GateDriver
from ..logging_config import logger

# Hard cap so a hung relay never ties up a worker.
_MAX_TIMEOUT = 15
_DEFAULT_TIMEOUT = 6


def _http_pulse(config: dict) -> Tuple[bool, str]:
    """Fire a single HTTP request at a relay. Used by both HTTP and GSM drivers
    (GSM just points at an HTTP→SMS gateway)."""
    url = (config or {}).get("url") or (config or {}).get("gateway_url")
    if not url:
        return False, "No relay URL configured"

    method = str((config or {}).get("method", "GET")).upper()
    headers = (config or {}).get("headers") or {}
    body = (config or {}).get("body")
    verify_tls = (config or {}).get("verify_tls", True)
    try:
        timeout = min(float((config or {}).get("timeout", _DEFAULT_TIMEOUT)), _MAX_TIMEOUT)
    except (TypeError, ValueError):
        timeout = _DEFAULT_TIMEOUT

    try:
        resp = requests.request(
            method,
            url,
            headers=headers,
            data=body if method != "GET" else None,
            timeout=timeout,
            verify=verify_tls,
        )
        if 200 <= resp.status_code < 300:
            return True, f"Relay responded {resp.status_code}"
        return False, f"Relay responded {resp.status_code}: {resp.text[:120]}"
    except requests.exceptions.Timeout:
        return False, f"Relay timed out after {timeout:.0f}s"
    except requests.exceptions.RequestException as e:
        return False, f"Relay unreachable: {e.__class__.__name__}"


def trigger_gate(driver: GateDriver, config: dict) -> Tuple[bool, str]:
    """Open the gate. Returns (ok, human-readable detail). Never raises."""
    try:
        if driver == GateDriver.MANUAL:
            return True, "Manual gate — opened by guard (logged only)"
        if driver in (GateDriver.HTTP, GateDriver.GSM):
            return _http_pulse(config)
        return False, f"Unknown driver {driver}"
    except Exception as e:  # defensive: a driver bug must not 500 the open call
        logger.exception("Gate driver crashed")
        return False, f"Driver error: {e.__class__.__name__}"
