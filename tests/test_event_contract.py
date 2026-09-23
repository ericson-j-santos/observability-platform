import json
import unittest
from pathlib import Path

from observability_platform.event import build_event


class EventContractTests(unittest.TestCase):
    def test_builds_versioned_redacted_event(self):
        event = build_event(
            event_name="e2e.probe",
            service_name="test-service",
            service_version="1.0.0",
            environment="test",
            correlation_id="cid-123",
            attributes={"token": "secret-value", "result": "ok"},
        )
        self.assertEqual(event["schema_version"], "observability.event/v1")
        self.assertEqual(event["correlation_id"], "cid-123")
        self.assertEqual(event["attributes"]["token"], "[REDACTED]")
        self.assertNotIn("secret-value", json.dumps(event))

    def test_rejects_missing_correlation_id(self):
        with self.assertRaisesRegex(ValueError, "correlation_id_required"):
            build_event(
                event_name="e2e.probe",
                service_name="test-service",
                environment="test",
                correlation_id=" ",
            )

    def test_schema_declares_required_correlation_and_no_extra_fields(self):
        schema = json.loads(Path("contracts/observability-event.schema.json").read_text())
        self.assertIn("correlation_id", schema["required"])
        self.assertFalse(schema["additionalProperties"])


if __name__ == "__main__":
    unittest.main()
