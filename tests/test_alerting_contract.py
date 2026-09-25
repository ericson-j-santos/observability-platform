import unittest
from pathlib import Path


class AlertingContractTests(unittest.TestCase):
    def test_alertmanager_is_loopback_only_and_has_no_external_receiver(self):
        compose = Path("compose.dev.yml").read_text(encoding="utf-8")
        config = Path("alertmanager/alertmanager.dev.yml").read_text(encoding="utf-8").lower()

        self.assertIn("prom/alertmanager:v0.34.1", compose)
        self.assertIn('"127.0.0.1:9093:9093"', compose)
        self.assertIn("./alertmanager/alertmanager.dev.yml:/etc/alertmanager/alertmanager.yml:ro", compose)
        self.assertIn("receiver: dev-null", config)
        for forbidden in ("webhook_configs", "email_configs", "slack_configs", "pagerduty_configs"):
            self.assertNotIn(forbidden, config)

    def test_prometheus_routes_alerts_and_loads_versioned_rule(self):
        prometheus = Path("prometheus/prometheus.dev.yml").read_text(encoding="utf-8")
        rules = Path("prometheus/rules/observability.dev.yml").read_text(encoding="utf-8")

        self.assertIn("evaluation_interval: 5s", prometheus)
        self.assertIn("/etc/prometheus/rules/*.yml", prometheus)
        self.assertIn('targets: ["alertmanager:9093"]', prometheus)
        self.assertIn("alert: ObservabilityCollectorUnavailable", rules)
        self.assertIn('up{job="observability-collector-otlp-metrics"} == 0', rules)
        self.assertIn("for: 5s", rules)

    def test_e2e_is_destructive_only_to_collector_and_always_restores_it(self):
        script = Path("scripts/e2e_alert_lifecycle.py").read_text(encoding="utf-8")
        self.assertIn('compose("stop", "collector")', script)
        self.assertIn('compose("start", "collector")', script)
        self.assertIn("finally:", script)
        self.assertNotIn('compose("down"', script)
        self.assertIn("wait_for_alert(False)", script)
        self.assertIn("wait_for_alert(True)", script)
        self.assertIn('"resolved_observed": True', script)

    def test_ci_requires_alert_lifecycle_before_evidence_gate(self):
        workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("Alert lifecycle validation", workflow)
        self.assertIn(
            "python scripts/e2e_alert_lifecycle.py --output artifacts/e2e-platform/alert-lifecycle.json",
            workflow,
        )
        self.assertIn("path: artifacts/e2e-platform/", workflow)


if __name__ == "__main__":
    unittest.main()
