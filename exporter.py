#!/usr/bin/env python3
"""
CipherTrust Manager Key Metrics Prometheus Exporter
Polls the CM REST API and exposes key metadata as Prometheus metrics.
Compatible with CM 2.20.x
"""

import logging
import os
import time
from datetime import datetime, timezone

import requests
import urllib3
from prometheus_client import (
    PLATFORM_COLLECTOR,
    PROCESS_COLLECTOR,
    REGISTRY,
    Gauge,
    Info,
    start_http_server,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
CM_HOST = os.environ.get("CM_HOST", "")
CM_USER = os.environ.get("CM_USER", "admin")
CM_PASS = os.environ.get("CM_PASS", "")
CM_PORT = os.environ.get("CM_PORT", "443")
SCRAPE_INT = int(os.environ.get("SCRAPE_INTERVAL", "60"))
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "9123"))
SSL_VERIFY = os.environ.get("SSL_VERIFY", "false").lower() != "false"

BASE_URL = f"https://{CM_HOST}:{CM_PORT}/api/v1"

# ── Remove noisy default collectors ──────────────────────────────────────────
REGISTRY.unregister(PROCESS_COLLECTOR)
REGISTRY.unregister(PLATFORM_COLLECTOR)
try:
    from prometheus_client import GC_COLLECTOR

    REGISTRY.unregister(GC_COLLECTOR)
except Exception:
    pass

# ── Metrics ───────────────────────────────────────────────────────────────────
cm_keys_total = Gauge(
    "cm_keys_total",
    "Number of keys by state, algorithm and domain",
    ["state", "algorithm", "domain"],
)
cm_keys_by_object_type = Gauge(
    "cm_keys_by_object_type", "Number of keys by object type", ["object_type", "domain"]
)
cm_keys_by_size = Gauge(
    "cm_keys_by_size", "Number of keys by key size (bits)", ["size", "algorithm"]
)
cm_keys_by_usage = Gauge("cm_keys_by_usage", "Number of keys by usage type", ["usage"])
cm_keys_unexportable = Gauge(
    "cm_keys_unexportable_total", "Number of keys marked as unexportable"
)
cm_keys_undeletable = Gauge(
    "cm_keys_undeletable_total", "Number of keys marked as undeletable"
)
cm_keys_never_exportable = Gauge(
    "cm_keys_never_exportable_total", "Number of keys marked as never exportable"
)
cm_keys_never_exported = Gauge(
    "cm_keys_never_exported_total", "Number of keys that have never been exported"
)
cm_keys_rotated = Gauge(
    "cm_keys_rotated_total",
    "Number of keys that have been rotated at least once (version > 0)",
)
cm_keys_rotation_versions = Gauge(
    "cm_keys_rotation_versions", "Total sum of all key versions (rotation depth)"
)
cm_keys_expiring_soon = Gauge(
    "cm_keys_expiring_soon_total",
    "Number of active keys expiring within N days",
    ["within_days"],
)
cm_keys_older_than = Gauge(
    "cm_keys_older_than_total",
    "Number of keys created more than N days ago",
    ["older_than_days"],
)
cm_keys_scrape_success = Gauge(
    "cm_keys_scrape_success", "1 if the last scrape succeeded, 0 if it failed"
)
cm_keys_scrape_duration_seconds = Gauge(
    "cm_keys_scrape_duration_seconds", "Duration of the last CM key scrape in seconds"
)

# Per-key inventory — one gauge per key, all metadata as labels, value=1
cm_key_info = Gauge(
    "cm_key_info",
    "Per-key inventory with metadata as labels",
    [
        "name",
        "uuid",
        "state",
        "algorithm",
        "size",
        "object_type",
        "usage",
        "domain",
        "version",
        "created_at",
        "activation_date",
        "deactivation_date",
        "unexportable",
        "undeletable",
        "never_exportable",
    ],
)


# ── CM API helpers ────────────────────────────────────────────────────────────


def get_token():
    url = f"{BASE_URL}/auth/tokens"
    resp = requests.post(
        url, json={"name": CM_USER, "password": CM_PASS}, verify=SSL_VERIFY, timeout=15
    )
    resp.raise_for_status()
    data = resp.json()
    token = data.get("jwt") or data.get("access_token")
    if not token:
        raise ValueError(f"No token in auth response: {list(data.keys())}")
    return token


def get_all_keys(token):
    headers = {"Authorization": f"Bearer {token}"}
    keys = []
    skip = 0
    limit = 500
    while True:
        resp = requests.get(
            f"{BASE_URL}/vault/keys2",
            headers=headers,
            params={"skip": skip, "limit": limit},
            verify=SSL_VERIFY,
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        batch = data.get("resources") or []
        keys.extend(batch)
        total = data.get("total", 0)
        skip += limit
        if skip >= total or not batch:
            break
    log.info(f"Fetched {len(keys)} keys from CM")
    return keys


def fmt_date(val):
    """Trim datetime to date-only string for cleaner labels."""
    if not val:
        return ""
    try:
        return val[:10]  # "2026-02-17T..." → "2026-02-17"
    except Exception:
        return str(val)


# ── Metric collection ─────────────────────────────────────────────────────────


def collect_metrics():
    start = time.time()
    try:
        keys = get_all_keys(get_token())

        # Clear all gauge label sets
        cm_keys_total.clear()
        cm_keys_by_object_type.clear()
        cm_keys_by_size.clear()
        cm_keys_by_usage.clear()
        cm_key_info.clear()

        now = datetime.now(timezone.utc)
        state_algo_domain = {}
        obj_type_domain = {}
        size_algo = {}
        usage_counts = {}

        unexportable = undeletable = never_exportable = never_exported = 0
        rotated = total_versions = 0
        expiring_30 = expiring_60 = expiring_90 = 0
        older_90 = older_180 = older_365 = 0

        for key in keys:
            state = key.get("state", "Unknown")
            algorithm = key.get("algorithm", "Unknown")
            domain = key.get("domain", "root")
            obj_type = key.get("objectType", "Unknown")
            size = str(key.get("size", "Unknown"))
            usage = key.get("usage", "Unknown")
            version = key.get("version", 0) or 0
            name = key.get("name", "")
            uuid = key.get("uuid", "")
            created_at = fmt_date(key.get("createdAt"))
            act_date = fmt_date(key.get("activationDate"))
            deact_date = fmt_date(
                key.get("deactivationDate") or key.get("deactivation_date")
            )

            is_unexportable = str(bool(key.get("unexportable"))).lower()
            is_undeletable = str(bool(key.get("undeletable"))).lower()
            is_never_exportable = str(bool(key.get("neverExportable"))).lower()

            # ── Aggregates ──
            state_algo_domain[(state, algorithm, domain)] = (
                state_algo_domain.get((state, algorithm, domain), 0) + 1
            )
            obj_type_domain[(obj_type, domain)] = (
                obj_type_domain.get((obj_type, domain), 0) + 1
            )
            size_algo[(size, algorithm)] = size_algo.get((size, algorithm), 0) + 1
            usage_counts[usage] = usage_counts.get(usage, 0) + 1

            if key.get("unexportable"):
                unexportable += 1
            if key.get("undeletable"):
                undeletable += 1
            if key.get("neverExportable"):
                never_exportable += 1
            if key.get("neverExported"):
                never_exported += 1

            if version > 0:
                rotated += 1
            total_versions += version

            if state == "Active" and deact_date:
                try:
                    delta = (
                        datetime.fromisoformat(deact_date + "T00:00:00+00:00") - now
                    ).days
                    if 0 <= delta <= 30:
                        expiring_30 += 1
                    if 0 <= delta <= 60:
                        expiring_60 += 1
                    if 0 <= delta <= 90:
                        expiring_90 += 1
                except Exception:
                    pass

            if created_at:
                try:
                    age = (
                        now - datetime.fromisoformat(created_at + "T00:00:00+00:00")
                    ).days
                    if age > 90:
                        older_90 += 1
                    if age > 180:
                        older_180 += 1
                    if age > 365:
                        older_365 += 1
                except Exception:
                    pass

            # ── Per-key inventory gauge ──
            cm_key_info.labels(
                name=name,
                uuid=uuid,
                state=state,
                algorithm=algorithm,
                size=size,
                object_type=obj_type,
                usage=usage,
                domain=domain,
                version=str(version),
                created_at=created_at,
                activation_date=act_date,
                deactivation_date=deact_date,
                unexportable=is_unexportable,
                undeletable=is_undeletable,
                never_exportable=is_never_exportable,
            ).set(1)

        # ── Write aggregate gauges ────────────────────────────────────────────
        for (state, algorithm, domain), count in state_algo_domain.items():
            cm_keys_total.labels(state=state, algorithm=algorithm, domain=domain).set(
                count
            )
        for (obj_type, domain), count in obj_type_domain.items():
            cm_keys_by_object_type.labels(object_type=obj_type, domain=domain).set(
                count
            )
        for (size, algorithm), count in size_algo.items():
            cm_keys_by_size.labels(size=size, algorithm=algorithm).set(count)
        for usage, count in usage_counts.items():
            cm_keys_by_usage.labels(usage=usage).set(count)

        cm_keys_unexportable.set(unexportable)
        cm_keys_undeletable.set(undeletable)
        cm_keys_never_exportable.set(never_exportable)
        cm_keys_never_exported.set(never_exported)
        cm_keys_rotated.set(rotated)
        cm_keys_rotation_versions.set(total_versions)
        cm_keys_expiring_soon.labels(within_days="30").set(expiring_30)
        cm_keys_expiring_soon.labels(within_days="60").set(expiring_60)
        cm_keys_expiring_soon.labels(within_days="90").set(expiring_90)
        cm_keys_older_than.labels(older_than_days="90").set(older_90)
        cm_keys_older_than.labels(older_than_days="180").set(older_180)
        cm_keys_older_than.labels(older_than_days="365").set(older_365)

        cm_keys_scrape_success.set(1)
        log.info(
            f"Scrape complete: {len(keys)} keys | rotated={rotated} | "
            f"unexportable={unexportable} | undeletable={undeletable}"
        )

    except Exception as e:
        cm_keys_scrape_success.set(0)
        log.error(f"Scrape failed: {e}")
    finally:
        cm_keys_scrape_duration_seconds.set(time.time() - start)


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if not CM_HOST or not CM_PASS:
        log.error("CM_HOST and CM_PASS environment variables are required")
        exit(1)
    log.info(f"Starting CM Key exporter on :{LISTEN_PORT}, polling every {SCRAPE_INT}s")
    start_http_server(LISTEN_PORT)
    while True:
        collect_metrics()
        time.sleep(SCRAPE_INT)
