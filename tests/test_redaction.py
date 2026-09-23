import unittest

from observability_platform.redaction import redact, safe_error


class RedactionTests(unittest.TestCase):
    def test_redacts_sensitive_keys_and_personal_data(self):
        payload = {
            "password": "super-secret",
            "Authorization": "Bearer abc.def.ghi",
            "email": "person@example.com",
            "cpf": "123.456.789-09",
            "phone": "+55 11 91234-5678",
            "nested": {"api_key": "key-123"},
        }
        sanitized = redact(payload)
        rendered = repr(sanitized)
        for forbidden in (
            "super-secret",
            "abc.def.ghi",
            "person@example.com",
            "123.456.789-09",
            "91234-5678",
            "key-123",
        ):
            self.assertNotIn(forbidden, rendered)
        self.assertIn("[REDACTED]", rendered)

    def test_safe_error_does_not_expose_exception_message(self):
        error = RuntimeError("token=should-never-appear")
        rendered = repr(safe_error(error))
        self.assertNotIn("should-never-appear", rendered)
        self.assertEqual(safe_error(error), {"type": "RuntimeError"})


if __name__ == "__main__":
    unittest.main()
