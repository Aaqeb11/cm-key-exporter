#!/usr/bin/env python3
"""
CipherTrust Manager Key Metrics Prometheus Exporter
Polls the CM REST API and exposes key metadata as Prometheus metrics.
Compatible with CM 2.20.x
"""

import logging
import os
import time

import requests
import urllib3
from prometheus_client import (
    PLATFORM_COLLECTOR,
    PROCESS_COLLECTOR,
    REGISTRY,
    Counter,
    Gauge,
    start_http_server,
)

# Suppress SSL warnings if verify is disabled
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# ── Config from environment ──────────────────────────────────────────────────
CM_HOST = os.environ.get("CM_HOST", "")
CM_USER = os.environ.get("CM_USER", "admin")
CM_PASS = os.environ.get("CM_PASS", "")
CM_PORT = os.environ.get("CM_PORT", "443")
SCRAPE_INT = int(os.environ.get("SCRAPE_INTERVAL", "60"))  # seconds
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "9123"))
SSL_VERIFY = os.environ.get("SSL_VERIFY", "false").lower() != "false"

BASE_URL = f"https://{CM_HOST}:{CM_PORT}/api/v1"

# ── Prometheus metrics ────────────────────────────────────────────────────────
# Remove default python/process collectors to keep output clean
REGISTRY.unregister(PROCESS_COLLECTOR)
REGISTRY.unregister(PLATFORM_COLLECTOR)
try:
    from prometheus_client import GC_COLLECTOR

    REGISTRY.unregister(GC_COLLECTOR)
except Exception:
    pass

cm_keys_total = Gauge(
    "cm_keys_total",
    "Total number of keys on CipherTrust Manager",
    ["state", "algorithm", "domain"],
)

cm_keys_scrape_success = Gauge(
    "cm_keys_scrape_success", "1 if the last scrape succeeded, 0 if it failed"
)

cm_keys_scrape_duration_seconds = Gauge(
    "cm_keys_scrape_duration_seconds", "Duration of the last CM key scrape in seconds"
)

cm_keys_expiring_soon = Gauge(
    "cm_keys_expiring_soon_total",
    "Number of keys expiring within N days",
    ["within_days"],
)


# ── CM API helpers ────────────────────────────────────────────────────────────


def get_token():
    """Authenticate and return a bearer token."""
    url = f"{BASE_URL}/auth/tokens"
    payload = {"name": CM_USER, "password": CM_PASS}
    resp = requests.post(url, json=payload, verify=SSL_VERIFY, timeout=15)
    log.info(f"Auth response status: {resp.status_code}")
    resp.raise_for_status()
    data = resp.json()
    log.info(f"Auth response keys: {list(data.keys())}")
    # CM may return 'jwt' or 'access_token'
    token = data.get("jwt") or data.get("access_token")
    if not token:
        raise ValueError(f"No token found in auth response: {data}")
    return token


def get_all_keys(token):
    """
    Page through /v1/vault/keys2 and return all key objects.
    CM default page size is 300; we walk until exhausted.
    """
    headers = {"Authorization": f"Bearer {token}"}
    keys = []
    skip = 0
    limit = 300

    while True:
        url = f"{BASE_URL}/vault/keys2"
        params = {"skip": skip, "limit": limit}
        resp = requests.get(
            url, headers=headers, params=params, verify=SSL_VERIFY, timeout=30
        )
        log.info(f"Keys API response status: {resp.status_code}")
        resp.raise_for_status()
        data = resp.json()
        log.info(f"Keys API response keys: {list(data.keys())}")
        batch = data.get("resources") or data.get("items") or []
        if batch and not keys:
            log.info(f"Sample key fields: {list(batch[0].keys())}")
            log.info(f"Sample key: {batch[0]}")
        keys.extend(batch)
        total = data.get("total", 0)
        log.info(f"Fetched {len(batch)} keys (total={total}, skip={skip})")
        skip += limit
        if skip >= total or not batch:
            break

    return keys


# ── Metric collection ─────────────────────────────────────────────────────────


def collect_metrics():
    """Fetch key data from CM and update Prometheus gauges."""
    start = time.time()

    try:
        token = get_token()
        keys = get_all_keys(token)

        # Reset all label combinations before re-populating
        cm_keys_total.clear()

        # Counters: {(state, algorithm, domain): count}
        counts = {}
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)
        expiring_30 = 0
        expiring_60 = 0
        expiring_90 = 0

        for key in keys:
            state = key.get("state", "Unknown")
            algorithm = key.get("algorithm", "Unknown")
            domain = key.get("domain", "root")

            bucket = (state, algorithm, domain)
            counts[bucket] = counts.get(bucket, 0) + 1

            # Expiry tracking
            deactivation_date = key.get("deactivationDate") or key.get(
                "deactivation_date"
            )
            if deactivation_date and state == "Active":
                try:
                    exp = datetime.fromisoformat(
                        deactivation_date.replace("Z", "+00:00")
                    )
                    delta_days = (exp - now).days
                    if 0 <= delta_days <= 30:
                        expiring_30 += 1
                    if 0 <= delta_days <= 60:
                        expiring_60 += 1
                    if 0 <= delta_days <= 90:
                        expiring_90 += 1
                except Exception:
                    pass

        for (state, algorithm, domain), count in counts.items():
            cm_keys_total.labels(state=state, algorithm=algorithm, domain=domain).set(
                count
            )

        cm_keys_expiring_soon.labels(within_days="30").set(expiring_30)
        cm_keys_expiring_soon.labels(within_days="60").set(expiring_60)
        cm_keys_expiring_soon.labels(within_days="90").set(expiring_90)

        cm_keys_scrape_success.set(1)
        log.info(f"Scraped {len(keys)} keys successfully")

    except Exception as e:
        cm_keys_scrape_success.set(0)
        log.error(f"Scrape failed: {e}")

    finally:
        cm_keys_scrape_duration_seconds.set(time.time() - start)


# ── Main loop ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if not CM_HOST or not CM_PASS:
        log.error("CM_HOST and CM_PASS environment variables are required")
        exit(1)

    log.info(
        f"Starting CM Key exporter on port {LISTEN_PORT}, polling every {SCRAPE_INT}s"
    )
    start_http_server(LISTEN_PORT)

    while True:
        collect_metrics()
        time.sleep(SCRAPE_INT)
