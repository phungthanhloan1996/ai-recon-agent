import unittest

from core.endpoint_registry import EndpointRegistry
from core.phase_admission import PhaseAdmission
from core.url_normalizer import URLNormalizer


class DummyState:
    def __init__(self):
        self.values = {
            "target": "https://example.com",
            "allowed_domains": ["example.com"],
        }

    def get(self, key, default=None):
        return self.values.get(key, default)


class EndpointAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.normalizer = URLNormalizer()
        self.registry = EndpointRegistry(self.normalizer)

    def test_duplicate_slashes_are_collapsed(self):
        normalized = self.normalizer.normalize_url("https://Example.com//api///v1//users")
        self.assertEqual(normalized, "https://example.com/api/v1/users")

    def test_default_ports_are_canonicalized(self):
        normalized = self.normalizer.normalize_url("https://Example.com:443/login")
        self.assertEqual(normalized, "https://example.com/login")

    def test_accidental_base_plus_absolute_join_is_salvaged(self):
        normalized = self.normalizer.normalize_url("https://example.com/http://api.example.com/users?id=1")
        self.assertEqual(normalized, "http://api.example.com/users?id=1")

    def test_embedded_absolute_url_in_path_is_rejected(self):
        normalized = self.normalizer.normalize_url("https://example.com/foo/http://bar.example.com")
        self.assertEqual(normalized, "")

    def test_off_scope_endpoint_is_rejected(self):
        admission = PhaseAdmission(DummyState())
        self.assertFalse(admission.is_valid_endpoint("https://evil.example.net/api/search?q=1"))
        self.assertTrue(admission.is_valid_endpoint("https://api.example.com/search?q=1"))

    def test_numeric_variants_share_wildcard_fingerprint(self):
        first = self.normalizer.normalize_endpoint("https://example.com/api/user?id=1&offset=10")
        second = self.normalizer.normalize_endpoint("https://example.com/api/user?id=2&offset=99")
        self.assertEqual(first["fingerprint"], second["fingerprint"])
        self.assertNotEqual(first["exact_fingerprint"], second["exact_fingerprint"])
        self.assertEqual(first["query_params"]["id"], ["1"])
        self.assertEqual(second["query_params"]["id"], ["2"])

    def test_registry_merges_parameter_variants(self):
        records = self.registry.register_many(
            [
                "https://example.com/api/user?id=1&offset=10",
                "https://example.com/api/user?id=2&offset=99",
            ]
        )
        self.assertEqual(len(records), 1)
        merged = records[0]
        self.assertEqual(merged["parameter_value_variants"]["id"], ["1", "2"])
        self.assertEqual(merged["parameter_value_variants"]["offset"], ["10", "99"])
        self.assertEqual(
            merged["normalized_url_variants"],
            [
                "https://example.com/api/user?id=1&offset=10",
                "https://example.com/api/user?id=2&offset=99",
            ],
        )


if __name__ == "__main__":
    unittest.main()
