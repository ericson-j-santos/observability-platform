import unittest
from pathlib import Path


class RuntimeContractTests(unittest.TestCase):
    def test_collector_has_three_signal_pipelines(self):
        text = Path("collector/config.dev.yaml").read_text()
        for signal in ("logs:", "metrics:", "traces:"):
            self.assertIn(signal, text)
        self.assertIn("otlphttp/loki", text)
        for exporter in ("file/logs", "file/metrics", "file/traces"):
            self.assertIn(exporter, text)

    def test_dev_network_keeps_internal_mesh_and_loopback_access(self):
        text = Path("compose.dev.yml").read_text()
        self.assertIn("observability:\n    internal: true", text)
        self.assertIn("host-access:", text)
        for port in ("3100", "4318", "13133", "8889", "9090", "3000"):
            self.assertIn(f'127.0.0.1:{port}', text)

    def test_collector_evidence_permissions_are_initialized_without_root_runtime(self):
        text = Path("compose.dev.yml").read_text()
        self.assertIn("collector-evidence-init:", text)
        self.assertIn('user: "0:0"', text)
        self.assertIn("chown -R 10001:10001 /evidence", text)
        self.assertIn('collector:\n    image: otel/opentelemetry-collector-contrib:0.128.0\n    user: "10001:10001"', text)
        self.assertIn("condition: service_completed_successfully", text)

    def test_signal_evidence_isolated_by_file(self):
        text = Path("collector/config.dev.yaml").read_text()
        self.assertIn("path: /evidence/logs.json", text)
        self.assertIn("path: /evidence/metrics.json", text)
        self.assertIn("path: /evidence/traces.json", text)

    def test_no_literal_secret_material_in_runtime_configs(self):
        paths = [
            Path("collector/config.dev.yaml"),
            Path("compose.dev.yml"),
            Path("grafana/provisioning/datasources/datasources.yml"),
            Path("prometheus/prometheus.dev.yml"),
            Path("loki/config.dev.yaml"),
        ]
        content = "\n".join(path.read_text().lower() for path in paths)
        for forbidden in (
            "bearer ",
            "password:",
            "api_key:",
            "connection_string:",
        ):
            self.assertNotIn(forbidden, content)


if __name__ == "__main__":
    unittest.main()
