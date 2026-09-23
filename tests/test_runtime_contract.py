import unittest
from pathlib import Path


class RuntimeContractTests(unittest.TestCase):
    def test_collector_has_three_signal_pipelines(self):
        text = Path("collector/config.dev.yaml").read_text()
        for signal in ("logs:", "metrics:", "traces:"):
            self.assertIn(signal, text)
        self.assertIn("otlphttp/loki", text)
        self.assertIn("file/evidence", text)

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
