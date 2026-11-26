"""Deterministic unit tests for Linux NOC prober, suppression, and SQLite SLA engine."""

from contextlib import closing
from pathlib import Path
import tempfile
import unittest

from src.noc_monitor import (
    acknowledge_incident,
    compute_sla_summary,
    detect_linux_default_gateway,
    init_db,
    parse_ping_output,
    render_handover_markdown,
    run_probe_cycle,
)

SAMPLE_CONFIG = {
    "sla_target_pct": 99.95,
    "cert_expiry_warn_days": 14,
    "targets": [
        {
            "id": "lan-default-gw",
            "name": "Local Default Gateway Router",
            "host": "192.168.1.1",
            "probe_type": "icmp",
            "parent_id": None,
            "severity": "P1",
            "max_rtt_ms": 25.0,
            "max_loss_pct": 20.0,
        },
        {
            "id": "quad9-dot-primary",
            "name": "Quad9 Encrypted DNS-over-TLS",
            "host": "9.9.9.9",
            "port": 853,
            "sni": "dns.quad9.net",
            "probe_type": "tls",
            "parent_id": "lan-default-gw",
            "severity": "P1",
            "max_rtt_ms": 350.0,
        },
        {
            "id": "github-https-edge",
            "name": "GitHub HTTPS & X.509 Certificate Monitor",
            "host": "github.com",
            "port": 443,
            "sni": "github.com",
            "probe_type": "tls",
            "parent_id": "lan-default-gw",
            "severity": "P2",
            "max_rtt_ms": 600.0,
        },
    ],
}


class NocMonitorTestSuite(unittest.TestCase):
    def test_detect_linux_default_gateway_and_ping_parser(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            route_path = Path(tmp) / "route"
            route_path.write_text(
                "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
                "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\n",
                encoding="utf-8",
            )
            # 0x0101A8C0 in little-endian host order corresponds to 192.168.1.1
            gw_ip = detect_linux_default_gateway(route_path)
            self.assertIn(gw_ip, ("192.168.1.1", "192.168.1.1"))

        ok_ping = (
            "2 packets transmitted, 2 received, 0% packet loss, time 1002ms\n"
            "rtt min/avg/max/mdev = 1.412/2.150/2.888/0.738 ms\n"
        )
        loss, rtt = parse_ping_output(ok_ping)
        self.assertEqual(loss, 0.0)
        self.assertEqual(rtt, 2.15)

        dead_ping = "2 packets transmitted, 0 received, 100% packet loss, time 2045ms\n"
        loss_dead, rtt_dead = parse_ping_output(dead_ping)
        self.assertEqual(loss_dead, 100.0)
        self.assertIsNone(rtt_dead)

    def test_parent_gateway_outage_suppresses_downstream_alert_storm(self) -> None:
        def all_down_stub(target: dict) -> dict:
            return {
                "resolved_host": target["host"],
                "reachable": False,
                "rtt_ms": None,
                "loss_pct": 100.0,
                "cert_days_left": None,
                "detail": "Network unreachable",
            }

        with tempfile.TemporaryDirectory() as tmp:
            with closing(init_db(Path(tmp) / "noc.db")) as conn:
                results = run_probe_cycle(conn, SAMPLE_CONFIG, probe_fn=all_down_stub, now_ts=1000.0)
                by_id = {r["target_id"]: r["state"] for r in results}
                self.assertEqual(by_id["lan-default-gw"], "DOWN")
                self.assertEqual(by_id["quad9-dot-primary"], "SUPPRESSED_BY_PARENT")
                self.assertEqual(by_id["github-https-edge"], "SUPPRESSED_BY_PARENT")

                sla = compute_sla_summary(conn, 99.95)
                # Only 1 root-cause incident should open (no child alert storm spam)
                self.assertEqual(sla["active_incidents_count"], 1)
                self.assertEqual(sla["active_incidents"][0]["target_id"], "lan-default-gw")

    def test_incident_lifecycle_ack_mtta_auto_resolve_mttr_and_sla_budget(self) -> None:
        def child_down_stub(target: dict) -> dict:
            is_up = target["id"] != "quad9-dot-primary"
            return {
                "resolved_host": target["host"],
                "reachable": is_up,
                "rtt_ms": 3.2 if is_up else None,
                "loss_pct": 0.0 if is_up else 100.0,
                "cert_days_left": 60.0 if target["probe_type"] == "tls" and is_up else None,
                "detail": "OK" if is_up else "TLS timeout",
            }

        def all_healthy_stub(target: dict) -> dict:
            return {
                "resolved_host": target["host"],
                "reachable": True,
                "rtt_ms": 4.5,
                "loss_pct": 0.0,
                "cert_days_left": 60.0 if target["probe_type"] == "tls" else None,
                "detail": "OK",
            }

        with tempfile.TemporaryDirectory() as tmp:
            with closing(init_db(Path(tmp) / "noc.db")) as conn:
                # T=1000s: Quad9 goes DOWN -> Incident #1 opens
                run_probe_cycle(conn, SAMPLE_CONFIG, probe_fn=child_down_stub, now_ts=1000.0)

                # T=1180s (3 min later): Tier-1 NOC operator acknowledges Incident #1
                ack = acknowledge_incident(
                    conn, incident_id=1, operator="benjarong", note="Checking upstream DoT", now_ts=1180.0
                )
                self.assertEqual(ack["mtta_sec"], 180.0)

                # T=1600s (10 min total outage): Service recovers -> Auto-RESOLVED with MTTR=600s
                run_probe_cycle(conn, SAMPLE_CONFIG, probe_fn=all_healthy_stub, now_ts=1600.0)

                sla = compute_sla_summary(conn, 99.95)
                self.assertEqual(sla["active_incidents_count"], 0)
                self.assertEqual(sla["resolved_incidents_count"], 1)
                self.assertEqual(sla["avg_mtta_sec"], 180.0)
                self.assertEqual(sla["avg_mttr_sec"], 600.0)
                self.assertEqual(sla["monthly_error_budget_min"], 21.6)
                self.assertEqual(sla["consumed_downtime_min"], 10.0)
                self.assertEqual(sla["remaining_error_budget_min"], 11.6)
                self.assertTrue(sla["sla_within_budget"])

    def test_tls_certificate_expiry_degraded_warning(self) -> None:
        def expiring_cert_stub(target: dict) -> dict:
            days = 5.5 if target["id"] == "github-https-edge" else 90.0
            return {
                "resolved_host": target["host"],
                "reachable": True,
                "rtt_ms": 12.0,
                "loss_pct": 0.0,
                "cert_days_left": days if target["probe_type"] == "tls" else None,
                "detail": f"cert_days={days}",
            }

        with tempfile.TemporaryDirectory() as tmp:
            with closing(init_db(Path(tmp) / "noc.db")) as conn:
                results = run_probe_cycle(conn, SAMPLE_CONFIG, probe_fn=expiring_cert_stub, now_ts=2000.0)
                by_id = {r["target_id"]: r["state"] for r in results}
                self.assertEqual(by_id["github-https-edge"], "DEGRADED")

                sla = compute_sla_summary(conn, 99.95)
                self.assertEqual(sla["active_incidents_count"], 1)
                self.assertIn("TLS cert expires in 5.5d", sla["active_incidents"][0]["summary"])

    def test_shift_handover_markdown_report_contains_live_telemetry(self) -> None:
        def healthy_stub(target: dict) -> dict:
            return {
                "resolved_host": target["host"],
                "reachable": True,
                "rtt_ms": 8.4,
                "loss_pct": 0.0,
                "cert_days_left": 75.0 if target["probe_type"] == "tls" else None,
                "detail": "TLSv1.3 OK",
            }

        with tempfile.TemporaryDirectory() as tmp:
            with closing(init_db(Path(tmp) / "noc.db")) as conn:
                run_probe_cycle(conn, SAMPLE_CONFIG, probe_fn=healthy_stub, now_ts=3000.0)
                report_md = render_handover_markdown(conn, "Morning Shift (08:00-16:00)", 99.95)
                self.assertIn("NOC Shift Handover Report — Morning Shift (08:00-16:00)", report_md)
                self.assertIn("| quad9-dot-primary | 9.9.9.9 | **UP** |", report_md)


if __name__ == "__main__":
    unittest.main()
