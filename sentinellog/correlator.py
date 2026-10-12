"""
Incident Correlation Engine for SentinelLog.

Aggregates related alerts by validated IPv4 and strict bounded rolling time window.
Enforces the anti-chaining rule so an incident's total span never exceeds window_minutes.
"""

import copy
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
import uuid

from sentinellog.config import DEFAULT_CONFIG
from sentinellog.parser import extract_ip


def _build_incident(
    source_ip: str,
    cluster: List[Dict[str, Any]],
    window_minutes: int,
) -> Dict[str, Any]:
    """Construct a correlated incident dictionary from an alert cluster."""
    first_seen = cluster[0]["timestamp"]
    last_seen = cluster[-1]["timestamp"]

    severity_ranks = DEFAULT_CONFIG.severity_rank
    highest_severity = max(
        (a.get("severity", "INFO").upper() for a in cluster),
        key=lambda s: severity_ranks.get(s, 0),
        default="INFO",
    )
    if highest_severity not in severity_ranks:
        highest_severity = "INFO"

    alert_ids = [a.get("alert_id") for a in cluster if a.get("alert_id")]
    alert_types = sorted({a.get("type", "unknown") for a in cluster})

    # Detect duplicate IDs safely
    seen_ids = set()
    has_duplicates = False
    for aid in alert_ids:
        if aid in seen_ids:
            has_duplicates = True
            break
        seen_ids.add(aid)

    reasons = [
        (
            f"Correlated {len(cluster)} security alert(s) from source IP "
            f"{source_ip} within {window_minutes} minutes."
        ),
        f"Alert types observed: {', '.join(alert_types)}.",
        (
            "Note: Correlated alerts represent related indicators requiring "
            "investigation; they do not prove malicious intent or human attribution."
        ),
    ]

    if has_duplicates:
        reasons.append(
            "Duplicate alert IDs were detected among linked alerts; "
            "all evidence entries were preserved."
        )

    evidence = [copy.deepcopy(a) for a in cluster]

    # Generate incident timeline: chronological ordering of events
    timeline = [
        {
            "timestamp": a.get("timestamp"),
            "alert_id": a.get("alert_id"),
            "type": a.get("type"),
            "severity": a.get("severity"),
            "message": a.get("message"),
        }
        for a in cluster
    ]

    # Deterministic incident UUID based on evidence seed (RFC 4122 v5 UUID)
    incident_seed = (
        f"sentinellog:{source_ip}:{first_seen}:{last_seen}:"
        f"{'-'.join(sorted(str(aid) for aid in alert_ids))}"
    )
    incident_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, incident_seed))

    return {
        "incident_id": incident_id,
        "source_ip": source_ip,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "severity": highest_severity,
        "alert_ids": alert_ids,
        "alert_count": len(cluster),
        "evidence": evidence,
        "timeline": timeline,
        "correlation_reasons": reasons,
    }


def correlate_alerts(
    alerts: List[Dict[str, Any]],
    window_minutes: int = DEFAULT_CONFIG.correlation_window_minutes,
) -> List[Dict[str, Any]]:
    """
    Correlate related security alerts into incidents using source IP and bounded time window.

    Rules:
    - Alerts must share an identical, validated IPv4 source address.
    - Alerts must have parseable ISO-style timestamps.
    - Strict bounded rolling window: last_seen - first_seen <= window_minutes.
      This prevents transitive chaining where events spaced 4 minutes apart could chain indefinitely.
    - Input dictionaries are preserved immutably.
    """
    if not isinstance(alerts, list):
        raise TypeError("alerts must be a list of alert dictionaries")

    if not isinstance(window_minutes, (int, float)) or isinstance(window_minutes, bool):
        raise TypeError("window_minutes must be an integer or float")

    if window_minutes <= 0:
        raise ValueError("window_minutes must be greater than zero")

    if not alerts:
        return []

    alerts_by_ip = {}
    window_delta = timedelta(minutes=window_minutes)

    for alert in alerts:
        if not isinstance(alert, dict):
            continue

        raw_ip = alert.get("source_ip")
        if not raw_ip or not isinstance(raw_ip, str):
            continue

        validated_ip = extract_ip(raw_ip)
        if not validated_ip or validated_ip != raw_ip:
            continue

        raw_timestamp = alert.get("timestamp")
        if not raw_timestamp or not isinstance(raw_timestamp, str):
            continue

        try:
            parsed_dt = datetime.strptime(raw_timestamp, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue

        alert_copy = copy.deepcopy(alert)
        alerts_by_ip.setdefault(validated_ip, []).append((parsed_dt, alert_copy))

    incidents = []

    # Deterministic grouping: sort by IP, then by timestamp and alert_id
    for source_ip in sorted(alerts_by_ip.keys()):
        ip_alerts = sorted(
            alerts_by_ip[source_ip],
            key=lambda item: (item[0], str(item[1].get("alert_id", ""))),
        )

        current_cluster = []
        cluster_start_dt = None

        for parsed_dt, alert in ip_alerts:
            if not current_cluster:
                current_cluster = [alert]
                cluster_start_dt = parsed_dt
            elif parsed_dt - cluster_start_dt <= window_delta:
                current_cluster.append(alert)
            else:
                incidents.append(
                    _build_incident(
                        source_ip=source_ip,
                        cluster=current_cluster,
                        window_minutes=window_minutes,
                    )
                )
                current_cluster = [alert]
                cluster_start_dt = parsed_dt

        if current_cluster:
            incidents.append(
                _build_incident(
                    source_ip=source_ip,
                    cluster=current_cluster,
                    window_minutes=window_minutes,
                )
            )

    return incidents
