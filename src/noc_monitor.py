"""Active network prober, parent-child alert correlator, and SQLite SLA incident CLI."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import socket
import sqlite3
import ssl
import struct
import subprocess
import time
from typing import Any, Callable

LOSS_RE = re.compile(r"(\d+(?:\.\d+)?)%\s*packet loss")
RTT_RE = re.compile(r"=\s*[\d.]+/([\d.]+)/[\d.]+/[\d.]+\s*ms")
MONTHLY_MINUTES = 30.0 * 24.0 * 60.0  # 43,200 minutes per 30-day SLA window


def detect_linux_default_gateway(route_file: Path = Path("/proc/net/route")) -> str:
    """Read the active IPv4 default gateway directly from the Linux kernel route table."""
    if route_file.exists():
        for line in route_file.read_text(encoding="utf-8").splitlines()[1:]:
            fields = line.strip().split()
            if len(fields) >= 4 and fields[1] == "00000000" and (int(fields[3], 16) & 0x2):
                return socket.inet_ntoa(struct.pack("=I", int(fields[2], 16)))
    return "1.1.1.1"


def parse_ping_output(stdout: str) -> tuple[float, float | None]:
    """Extract packet loss percentage and average RTT (ms) from iputils-ping output."""
    loss_match = LOSS_RE.search(stdout)
    loss_pct = float(loss_match.group(1)) if loss_match else 100.0
    rtt_match = RTT_RE.search(stdout)
    avg_rtt = float(rtt_match.group(1)) if rtt_match else None
    return loss_pct, avg_rtt


def probe_icmp(host: str, count: int = 2, timeout_sec: int = 2) -> dict[str, Any]:
    """Execute /bin/ping against a target host and return real packet loss and RTT."""
    try:
        proc = subprocess.run(
            ["ping", "-n", "-q", "-c", str(count), "-W", str(timeout_sec), host],
            capture_output=True,
            text=True,
            timeout=count * timeout_sec + 3,
            check=False,
        )
        loss_pct, avg_rtt = parse_ping_output(proc.stdout)
        reachable = proc.returncode == 0 and loss_pct < 100.0
        return {
            "reachable": reachable,
            "rtt_ms": avg_rtt,
            "loss_pct": loss_pct,
            "cert_days_left": None,
            "detail": f"loss={loss_pct:.0f}% rtt={avg_rtt}ms" if reachable else "ICMP timeout",
        }
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "reachable": False,
            "rtt_ms": None,
            "loss_pct": 100.0,
            "cert_days_left": None,
            "detail": f"ICMP error: {exc}",
        }


def probe_tls(host: str, port: int, sni: str, timeout_sec: float = 4.0) -> dict[str, Any]:
    """Measure TCP+TLS handshake latency and remaining X.509 certificate validity days."""
    ctx = ssl.create_default_context()
    t0 = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout_sec) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as tls_sock:
                rtt_ms = round((time.perf_counter() - t0) * 1000.0, 2)
                cert = tls_sock.getpeercert()
                not_after = cert.get("notAfter") if cert else None
                days_left = None
                if not_after:
                    exp_epoch = ssl.cert_time_to_seconds(not_after)
                    days_left = round((exp_epoch - time.time()) / 86400.0, 1)
                return {
                    "reachable": True,
                    "rtt_ms": rtt_ms,
                    "loss_pct": 0.0,
                    "cert_days_left": days_left,
                    "detail": f"{tls_sock.version()} rtt={rtt_ms}ms cert_days={days_left}",
                }
    except OSError as exc:
        return {
            "reachable": False,
            "rtt_ms": None,
            "loss_pct": 100.0,
            "cert_days_left": None,
            "detail": f"TLS probe failed: {exc}",
        }


def live_probe_dispatcher(target: dict[str, Any]) -> dict[str, Any]:
    """Dispatch the configured active probe type for a single target definition."""
    host = (
        detect_linux_default_gateway()
        if target["host"] == "auto_default_gateway"
        else target["host"]
    )
    if target["probe_type"] == "icmp":
        res = probe_icmp(host)
    elif target["probe_type"] == "tls":
        res = probe_tls(host, int(target["port"]), target.get("sni", host))
    else:
        raise ValueError(f"Unsupported probe_type: {target['probe_type']}")
    return {"resolved_host": host, **res}


def init_db(db_path: Path) -> sqlite3.Connection:
    """Initialize SQLite schema for time-series probe samples and incident tracking."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS probe_samples (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sampled_at REAL NOT NULL,
            target_id TEXT NOT NULL,
            resolved_host TEXT NOT NULL,
            state TEXT NOT NULL,
            rtt_ms REAL,
            loss_pct REAL,
            cert_days_left REAL,
            detail TEXT
        );

        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL,
            opened_at REAL NOT NULL,
            acked_at REAL,
            acked_by TEXT,
            ack_note TEXT,
            resolved_at REAL,
            mtta_sec REAL,
            mttr_sec REAL,
            summary TEXT NOT NULL
        );
        """
    )
    conn.commit()
    return conn


def evaluate_target_state(
    target: dict[str, Any],
    raw: dict[str, Any],
    cert_warn_days: int,
) -> tuple[str, str]:
    """Classify probe outcome into UP, DEGRADED, or DOWN with human-readable reason."""
    if not raw["reachable"]:
        return "DOWN", raw["detail"]

    reasons: list[str] = []
    max_loss = target.get("max_loss_pct")
    if max_loss is not None and (raw["loss_pct"] or 0.0) > float(max_loss):
        reasons.append(f"packet loss {raw['loss_pct']}% > {max_loss}%")

    max_rtt = target.get("max_rtt_ms")
    if max_rtt is not None and raw["rtt_ms"] is not None and raw["rtt_ms"] > float(max_rtt):
        reasons.append(f"RTT {raw['rtt_ms']}ms > {max_rtt}ms")

    if raw["cert_days_left"] is not None and raw["cert_days_left"] < cert_warn_days:
        reasons.append(f"TLS cert expires in {raw['cert_days_left']}d")

    if reasons:
        return "DEGRADED", "; ".join(reasons)
    return "UP", raw["detail"]


def run_probe_cycle(
    conn: sqlite3.Connection,
    config: dict[str, Any],
    probe_fn: Callable[[dict[str, Any]], dict[str, Any]] = live_probe_dispatcher,
    now_ts: float | None = None,
) -> list[dict[str, Any]]:
    """Probe targets in parent-first order, suppress child storms, and update incidents."""
    ts = now_ts if now_ts is not None else time.time()
    cert_warn = int(config.get("cert_expiry_warn_days", 14))
    ordered = sorted(config["targets"], key=lambda t: 0 if t.get("parent_id") is None else 1)

    states_by_id: dict[str, str] = {}
    results: list[dict[str, Any]] = []

    for target in ordered:
        tid = target["id"]
        parent_id = target.get("parent_id")
        raw = probe_fn(target)
        state, reason = evaluate_target_state(target, raw, cert_warn)

        if state != "UP" and parent_id and states_by_id.get(parent_id) == "DOWN":
            state = "SUPPRESSED_BY_PARENT"
            reason = f"Suppressed: upstream parent '{parent_id}' is DOWN"

        states_by_id[tid] = state
        conn.execute(
            """
            INSERT INTO probe_samples
            (sampled_at, target_id, resolved_host, state, rtt_ms, loss_pct, cert_days_left, detail)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ts,
                tid,
                raw.get("resolved_host", target["host"]),
                state,
                raw["rtt_ms"],
                raw["loss_pct"],
                raw["cert_days_left"],
                reason,
            ),
        )

        active = conn.execute(
            "SELECT * FROM incidents WHERE target_id = ? AND status IN ('OPEN', 'ACKNOWLEDGED')",
            (tid,),
        ).fetchone()

        if state in ("DOWN", "DEGRADED") and active is None:
            conn.execute(
                """
                INSERT INTO incidents (target_id, severity, status, opened_at, summary)
                VALUES (?, ?, 'OPEN', ?, ?)
                """,
                (tid, target["severity"], ts, f"[{state}] {target['name']}: {reason}"),
            )
        elif state == "UP" and active is not None:
            mttr = round(max(0.0, ts - float(active["opened_at"])), 2)
            conn.execute(
                "UPDATE incidents SET status = 'RESOLVED', resolved_at = ?, mttr_sec = ? WHERE id = ?",
                (ts, mttr, active["id"]),
            )

        results.append(
            {
                "target_id": tid,
                "host": raw.get("resolved_host", target["host"]),
                "state": state,
                "rtt_ms": raw["rtt_ms"],
                "cert_days_left": raw["cert_days_left"],
                "detail": reason,
            }
        )

    conn.commit()
    return results


def acknowledge_incident(
    conn: sqlite3.Connection,
    incident_id: int,
    operator: str,
    note: str,
    now_ts: float | None = None,
) -> dict[str, Any]:
    """Acknowledge an OPEN incident and record exact MTTA seconds."""
    ts = now_ts if now_ts is not None else time.time()
    row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if row is None:
        raise ValueError(f"Incident #{incident_id} not found")
    if row["status"] == "RESOLVED":
        raise ValueError(f"Incident #{incident_id} is already RESOLVED")

    mtta = round(max(0.0, ts - float(row["opened_at"])), 2)
    conn.execute(
        """
        UPDATE incidents
        SET status = 'ACKNOWLEDGED', acked_at = ?, acked_by = ?, ack_note = ?, mtta_sec = ?
        WHERE id = ?
        """,
        (ts, operator, note, mtta, incident_id),
    )
    conn.commit()
    return {"incident_id": incident_id, "status": "ACKNOWLEDGED", "acked_by": operator, "mtta_sec": mtta}


def compute_sla_summary(conn: sqlite3.Connection, sla_target_pct: float = 99.95) -> dict[str, Any]:
    """Compute rolling probe availability, MTTA, MTTR, and 30-day SLA error budget."""
    totals = conn.execute(
        """
        SELECT
            COUNT(*) AS total_samples,
            SUM(CASE WHEN state = 'UP' THEN 1 ELSE 0 END) AS up_samples
        FROM probe_samples
        WHERE state != 'SUPPRESSED_BY_PARENT'
        """
    ).fetchone()

    total_n = int(totals["total_samples"] or 0)
    up_n = int(totals["up_samples"] or 0)
    availability_pct = round((up_n / total_n) * 100.0, 3) if total_n > 0 else 100.0

    inc_stats = conn.execute(
        """
        SELECT
            SUM(CASE WHEN status IN ('OPEN', 'ACKNOWLEDGED') THEN 1 ELSE 0 END) AS active_count,
            SUM(CASE WHEN status = 'RESOLVED' THEN 1 ELSE 0 END) AS resolved_count,
            AVG(mtta_sec) AS avg_mtta_sec,
            AVG(mttr_sec) AS avg_mttr_sec,
            COALESCE(SUM(mttr_sec), 0.0) AS total_downtime_sec
        FROM incidents
        """
    ).fetchone()

    allowed_min = round(MONTHLY_MINUTES * (1.0 - sla_target_pct / 100.0), 2)
    used_min = round(float(inc_stats["total_downtime_sec"] or 0.0) / 60.0, 2)
    remaining_min = round(allowed_min - used_min, 2)

    active_rows = [
        dict(r)
        for r in conn.execute(
            "SELECT id, target_id, severity, status, summary, mtta_sec FROM incidents WHERE status != 'RESOLVED' ORDER BY id"
        ).fetchall()
    ]

    return {
        "sla_target_pct": sla_target_pct,
        "observed_availability_pct": availability_pct,
        "monthly_error_budget_min": allowed_min,
        "consumed_downtime_min": used_min,
        "remaining_error_budget_min": remaining_min,
        "sla_within_budget": remaining_min >= 0.0,
        "active_incidents_count": int(inc_stats["active_count"] or 0),
        "resolved_incidents_count": int(inc_stats["resolved_count"] or 0),
        "avg_mtta_sec": round(float(inc_stats["avg_mtta_sec"]), 2) if inc_stats["avg_mtta_sec"] is not None else None,
        "avg_mttr_sec": round(float(inc_stats["avg_mttr_sec"]), 2) if inc_stats["avg_mttr_sec"] is not None else None,
        "active_incidents": active_rows,
    }


def render_handover_markdown(conn: sqlite3.Connection, shift_name: str, sla_pct: float) -> str:
    """Generate a structured Markdown shift-handover report from live SQLite records."""
    sla = compute_sla_summary(conn, sla_pct)
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    latest = conn.execute(
        """
        SELECT target_id, resolved_host, state, rtt_ms, cert_days_left, detail
        FROM probe_samples
        WHERE id IN (SELECT MAX(id) FROM probe_samples GROUP BY target_id)
        ORDER BY target_id
        """
    ).fetchall()

    lines = [
        f"# NOC Shift Handover Report — {shift_name}",
        f"- **Generated (UTC):** {now_iso}",
        f"- **Observed Availability:** {sla['observed_availability_pct']}% (Target: {sla_pct}%)",
        f"- **30-Day SLA Error Budget:** {sla['remaining_error_budget_min']} / {sla['monthly_error_budget_min']} min remaining",
        f"- **Active Incidents:** {sla['active_incidents_count']} | **Resolved:** {sla['resolved_incidents_count']}",
        f"- **Mean MTTA / MTTR:** {sla['avg_mtta_sec']}s / {sla['avg_mttr_sec']}s",
        "",
        "## Latest Target Telemetry",
        "| Target ID | Host | State | RTT (ms) | TLS Cert (Days) | Detail |",
        "|---|---|---|---|---|---|",
    ]
    for r in latest:
        lines.append(
            f"| {r['target_id']} | {r['resolved_host']} | **{r['state']}** | "
            f"{r['rtt_ms']} | {r['cert_days_left']} | {r['detail']} |"
        )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Linux NOC Active Network & SLA Monitor CLI")
    parser.add_argument("--db", type=Path, default=Path("./noc_state.db"), help="SQLite state DB path")
    parser.add_argument(
        "--config",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "configs" / "targets.json",
        help="Path to targets.json configuration",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("probe", help="Execute a live probe cycle and update incident states")
    sub.add_parser("status", help="Print JSON SLA summary and active incident queue")

    ack_p = sub.add_parser("ack", help="Acknowledge an active incident and record MTTA")
    ack_p.add_argument("--incident-id", type=int, required=True)
    ack_p.add_argument("--operator", type=str, required=True)
    ack_p.add_argument("--note", type=str, default="Acknowledged by Tier-1 NOC")

    rep_p = sub.add_parser("handover", help="Print Markdown NOC shift handover report")
    rep_p.add_argument("--shift", type=str, default="Day Shift (08:00-16:00)")

    args = parser.parse_args()
    cfg = json.loads(args.config.read_text(encoding="utf-8"))
    conn = init_db(args.db)

    if args.cmd == "probe":
        out = run_probe_cycle(conn, cfg)
        print(json.dumps({"probe_results": out}, indent=2))
    elif args.cmd == "status":
        print(json.dumps(compute_sla_summary(conn, float(cfg.get("sla_target_pct", 99.95))), indent=2))
    elif args.cmd == "ack":
        print(json.dumps(acknowledge_incident(conn, args.incident_id, args.operator, args.note), indent=2))
    elif args.cmd == "handover":
        print(render_handover_markdown(conn, args.shift, float(cfg.get("sla_target_pct", 99.95))))


if __name__ == "__main__":
    main()
def render_handover_markdown(conn: sqlite3.Connection, shift_name: str, sla_pct: float) -> str:
    """Generate a structured Markdown shift-handover report from live SQLite records."""
    sla = compute_sla_summary(conn, sla_pct)
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    mtta_str = f"{sla['avg_mtta_sec']}s" if sla["avg_mtta_sec"] is not None else "N/A"
    mttr_str = f"{sla['avg_mttr_sec']}s" if sla["avg_mttr_sec"] is not None else "N/A"

    latest = conn.execute(
        """
        SELECT target_id, resolved_host, state, rtt_ms, cert_days_left, detail
        FROM probe_samples
        WHERE id IN (SELECT MAX(id) FROM probe_samples GROUP BY target_id)
        ORDER BY target_id
        """
    ).fetchall()

    lines = [
        f"# NOC Shift Handover Report — {shift_name}",
        f"- **Generated (UTC):** {now_iso}",
        f"- **Observed Availability:** {sla['observed_availability_pct']}% (Target: {sla_pct}%)",
        f"- **30-Day SLA Error Budget:** {sla['remaining_error_budget_min']} / {sla['monthly_error_budget_min']} min remaining",
        f"- **Active Incidents:** {sla['active_incidents_count']} | **Resolved:** {sla['resolved_incidents_count']}",
        f"- **Mean MTTA / MTTR:** {mtta_str} / {mttr_str}",
        "",
        "## Latest Target Telemetry",
        "| Target ID | Host | State | RTT (ms) | TLS Cert (Days) | Detail |",
        "|---|---|---|---|---|---|",
    ]
    for r in latest:
        rtt_str = f"{r['rtt_ms']}" if r["rtt_ms"] is not None else "-"
        cert_str = f"{r['cert_days_left']}" if r["cert_days_left"] is not None else "-"
        lines.append(
            f"| {r['target_id']} | {r['resolved_host']} | **{r['state']}** | "
            f"{rtt_str} | {cert_str} | {r['detail']} |"
        )
    return "\n".join(lines)
