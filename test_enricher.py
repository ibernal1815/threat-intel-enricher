"""
test suite for threat-intel-enricher
all API calls are mocked — no real keys needed to run these.
"""

import json
import sys
import os
import unittest
from unittest.mock import patch, MagicMock

# add parent dir to path so imports resolve without installing the package
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import vt
import abuseipdb
import reporter
import config
from enricher import detect_ioc_type, parse_ioc_input, load_iocs_from_file


# ── fixtures ────────────────────────────────────────────────────────────────

# what a typical VT IP response looks like (trimmed for brevity)
VT_IP_RESPONSE_MALICIOUS = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious": 15,
                "suspicious": 2,
                "undetected": 10,
                "harmless": 5,
                "timeout": 0,
            },
            "tags": ["tor-exit-node", "scanner"],
            "categories": {"Forcepoint ThreatSeeker": "malicious sites"},
        }
    }
}

VT_IP_RESPONSE_CLEAN = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious": 0,
                "suspicious": 0,
                "undetected": 40,
                "harmless": 30,
                "timeout": 0,
            },
            "tags": [],
            "categories": {},
        }
    }
}

VT_DOMAIN_RESPONSE_SUSPICIOUS = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious": 5,
                "suspicious": 1,
                "undetected": 50,
                "harmless": 20,
                "timeout": 0,
            },
            "tags": ["phishing"],
            "categories": {"Sophos": "phishing"},
        }
    }
}

VT_HASH_RESPONSE_MALICIOUS = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious": 45,
                "suspicious": 3,
                "undetected": 10,
                "harmless": 0,
                "timeout": 2,
            },
            "tags": ["ransomware", "trojan"],
            "categories": {},
        }
    }
}

ABUSE_RESPONSE_MALICIOUS = {
    "data": {
        "abuseConfidenceScore": 95,
        "totalReports": 142,
        "countryCode": "NL",
        "isp": "Frantech Solutions",
        "usageType": "Data Center/Web Hosting/Transit",
        "isTor": True,
        "reports": [
            {"categories": [18, 22]},
            {"categories": [14, 15]},
        ],
    }
}

ABUSE_RESPONSE_CLEAN = {
    "data": {
        "abuseConfidenceScore": 0,
        "totalReports": 0,
        "countryCode": "US",
        "isp": "Google LLC",
        "usageType": "Search Engine Spider",
        "isTor": False,
        "reports": [],
    }
}


# ── IOC type detection ───────────────────────────────────────────────────────

class TestDetectIocType(unittest.TestCase):

    def test_valid_ipv4(self):
        self.assertEqual(detect_ioc_type("185.220.101.5"), "ip")
        self.assertEqual(detect_ioc_type("8.8.8.8"), "ip")
        self.assertEqual(detect_ioc_type("192.168.1.1"), "ip")

    def test_valid_domain(self):
        self.assertEqual(detect_ioc_type("malicious.example.com"), "domain")
        self.assertEqual(detect_ioc_type("evil.io"), "domain")
        self.assertEqual(detect_ioc_type("sub.domain.co.uk"), "domain")

    def test_valid_md5(self):
        self.assertEqual(detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e"), "hash")

    def test_valid_sha1(self):
        self.assertEqual(detect_ioc_type("da39a3ee5e6b4b0d3255bfef95601890afd80709"), "hash")

    def test_valid_sha256(self):
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.assertEqual(detect_ioc_type(sha256), "hash")

    def test_unrecognized_returns_none(self):
        self.assertIsNone(detect_ioc_type("not-an-ioc"))
        self.assertIsNone(detect_ioc_type(""))
        self.assertIsNone(detect_ioc_type("zzz"))
        self.assertIsNone(detect_ioc_type("plaintext"))
        self.assertIsNone(detect_ioc_type("http://example.com"))  # URLs not supported, strip first

    def test_out_of_range_ip_still_matches_format(self):
        # the regex does format-matching, not semantic validation — VT will handle bad IPs
        # 999.999.999.999 matches the pattern even though it's not a valid routable IP
        self.assertEqual(detect_ioc_type("999.999.999.999"), "ip")

    def test_strips_whitespace(self):
        self.assertEqual(detect_ioc_type("  8.8.8.8  "), "ip")


class TestParseIocInput(unittest.TestCase):

    def test_mixed_iocs(self):
        raw = ["1.2.3.4", "evil.com", "d41d8cd98f00b204e9800998ecf8427e", "garbage!!!"]
        result = parse_ioc_input(raw)
        types = [r["type"] for r in result]
        self.assertIn("ip", types)
        self.assertIn("domain", types)
        self.assertIn("hash", types)
        self.assertEqual(len(result), 3)  # garbage should be skipped

    def test_empty_list(self):
        self.assertEqual(parse_ioc_input([]), [])

    def test_deduplication_not_done_here(self):
        # dedup is the caller's responsibility, parser just types them
        raw = ["1.2.3.4", "1.2.3.4"]
        result = parse_ioc_input(raw)
        self.assertEqual(len(result), 2)


# ── VirusTotal module ────────────────────────────────────────────────────────

class TestVtParsing(unittest.TestCase):

    def test_parse_malicious_ip(self):
        result = vt._parse_result(VT_IP_RESPONSE_MALICIOUS, ioc_type="ip")
        self.assertEqual(result["vt_detection_count"], 17)  # 15 malicious + 2 suspicious
        self.assertEqual(result["vt_total_engines"], 32)
        self.assertIn("tor-exit-node", result["vt_tags"])
        self.assertIn("malicious sites", result["vt_categories"])

    def test_parse_clean_ip(self):
        result = vt._parse_result(VT_IP_RESPONSE_CLEAN, ioc_type="ip")
        self.assertEqual(result["vt_detection_count"], 0)

    def test_parse_error_response(self):
        result = vt._parse_result({"error": "http_404"}, ioc_type="ip")
        self.assertIn("vt_error", result)
        self.assertIsNone(result["vt_detection_count"])

    def test_parse_categories_dict_to_list(self):
        result = vt._parse_result(VT_DOMAIN_RESPONSE_SUSPICIOUS, ioc_type="domain")
        self.assertIsInstance(result["vt_categories"], list)
        self.assertIn("phishing", result["vt_categories"])

    @patch("vt._get")
    def test_lookup_ip_calls_correct_endpoint(self, mock_get):
        mock_get.return_value = VT_IP_RESPONSE_CLEAN
        vt.lookup_ip("8.8.8.8")
        mock_get.assert_called_once_with("/ip_addresses/8.8.8.8")

    @patch("vt._get")
    def test_lookup_domain_calls_correct_endpoint(self, mock_get):
        mock_get.return_value = VT_IP_RESPONSE_CLEAN
        vt.lookup_domain("example.com")
        mock_get.assert_called_once_with("/domains/example.com")

    @patch("vt._get")
    def test_lookup_hash_calls_correct_endpoint(self, mock_get):
        mock_get.return_value = VT_IP_RESPONSE_CLEAN
        vt.lookup_hash("d41d8cd98f00b204e9800998ecf8427e")
        mock_get.assert_called_once_with("/files/d41d8cd98f00b204e9800998ecf8427e")


# ── AbuseIPDB module ─────────────────────────────────────────────────────────

class TestAbuseIpdbParsing(unittest.TestCase):

    def test_parse_malicious_ip(self):
        result = abuseipdb._parse_result(ABUSE_RESPONSE_MALICIOUS)
        self.assertEqual(result["abuse_confidence_score"], 95)
        self.assertEqual(result["abuse_total_reports"], 142)
        self.assertTrue(result["abuse_is_tor"])
        self.assertEqual(result["abuse_country"], "NL")
        self.assertEqual(result["abuse_isp"], "Frantech Solutions")
        # categories from codes 14, 15, 18, 22
        self.assertIn("Port Scan", result["abuse_categories"])
        self.assertIn("Brute-Force", result["abuse_categories"])

    def test_parse_clean_ip(self):
        result = abuseipdb._parse_result(ABUSE_RESPONSE_CLEAN)
        self.assertEqual(result["abuse_confidence_score"], 0)
        self.assertEqual(result["abuse_total_reports"], 0)
        self.assertFalse(result["abuse_is_tor"])
        self.assertEqual(result["abuse_categories"], [])

    def test_unknown_category_codes_handled(self):
        response = {
            "data": {
                "abuseConfidenceScore": 50,
                "totalReports": 3,
                "countryCode": "XX",
                "isp": "Unknown ISP",
                "usageType": "",
                "isTor": False,
                "reports": [{"categories": [999]}],  # bogus code
            }
        }
        result = abuseipdb._parse_result(response)
        self.assertIn("unknown_category_999", result["abuse_categories"])


# ── verdict logic ────────────────────────────────────────────────────────────

class TestVerdictLogic(unittest.TestCase):

    def _make_vt(self, count):
        return {"vt_detection_count": count}

    def _make_abuse(self, score, is_tor=False):
        return {"abuse_confidence_score": score, "abuse_is_tor": is_tor}

    def test_clean_ip_both_sources(self):
        verdict = reporter.determine_verdict("ip", self._make_vt(0), self._make_abuse(0))
        self.assertEqual(verdict, "clean")

    def test_malicious_by_vt(self):
        verdict = reporter.determine_verdict("ip", self._make_vt(15), self._make_abuse(0))
        self.assertEqual(verdict, "malicious")

    def test_malicious_by_abuse(self):
        verdict = reporter.determine_verdict("ip", self._make_vt(0), self._make_abuse(80))
        self.assertEqual(verdict, "malicious")

    def test_suspicious_by_vt(self):
        verdict = reporter.determine_verdict("ip", self._make_vt(5), self._make_abuse(0))
        self.assertEqual(verdict, "suspicious")

    def test_suspicious_by_abuse(self):
        verdict = reporter.determine_verdict("ip", self._make_vt(0), self._make_abuse(30))
        self.assertEqual(verdict, "suspicious")

    def test_tor_node_is_suspicious(self):
        verdict = reporter.determine_verdict("ip", self._make_vt(0), self._make_abuse(0, is_tor=True))
        self.assertEqual(verdict, "suspicious")

    def test_malicious_beats_suspicious(self):
        # one source says malicious, other says suspicious — should be malicious
        verdict = reporter.determine_verdict("ip", self._make_vt(15), self._make_abuse(30))
        self.assertEqual(verdict, "malicious")

    def test_domain_no_abuse_data(self):
        verdict = reporter.determine_verdict("domain", self._make_vt(0))
        self.assertEqual(verdict, "clean")

    def test_hash_malicious_by_vt(self):
        verdict = reporter.determine_verdict("hash", self._make_vt(48))
        self.assertEqual(verdict, "malicious")

    def test_vt_none_detection_count(self):
        # VT returned an error, count is None — shouldn't crash
        vt_data = {"vt_detection_count": None, "vt_error": "http_404"}
        verdict = reporter.determine_verdict("ip", vt_data, self._make_abuse(0))
        self.assertEqual(verdict, "clean")


# ── reporter / record building ───────────────────────────────────────────────

class TestBuildIocRecord(unittest.TestCase):

    def test_ip_record_structure(self):
        vt_data = vt._parse_result(VT_IP_RESPONSE_MALICIOUS, "ip")
        abuse_data = abuseipdb._parse_result(ABUSE_RESPONSE_MALICIOUS)
        record = reporter.build_ioc_record("185.220.101.5", "ip", vt_data, abuse_data)

        self.assertEqual(record["ioc"], "185.220.101.5")
        self.assertEqual(record["type"], "ip")
        self.assertEqual(record["verdict"], "malicious")
        self.assertIn("virustotal", record)
        self.assertIn("abuseipdb", record)
        self.assertNotIn("_raw", record)  # not included unless asked

    def test_raw_included_when_requested(self):
        vt_data = vt._parse_result(VT_IP_RESPONSE_CLEAN, "ip")
        abuse_data = abuseipdb._parse_result(ABUSE_RESPONSE_CLEAN)
        record = reporter.build_ioc_record("8.8.8.8", "ip", vt_data, abuse_data, include_raw=True)
        self.assertIn("_raw", record)
        self.assertIn("virustotal", record["_raw"])

    def test_domain_record_has_not_applicable_abuseipdb(self):
        vt_data = vt._parse_result(VT_DOMAIN_RESPONSE_SUSPICIOUS, "domain")
        record = reporter.build_ioc_record("evil.com", "domain", vt_data)
        self.assertEqual(record["abuseipdb"], "not_applicable")

    def test_hash_record_structure(self):
        vt_data = vt._parse_result(VT_HASH_RESPONSE_MALICIOUS, "hash")
        record = reporter.build_ioc_record(
            "d41d8cd98f00b204e9800998ecf8427e", "hash", vt_data
        )
        self.assertEqual(record["type"], "hash")
        self.assertEqual(record["verdict"], "malicious")


class TestBuildReport(unittest.TestCase):

    def test_report_summary_counts(self):
        records = [
            {"ioc": "1.1.1.1", "type": "ip", "verdict": "clean"},
            {"ioc": "evil.com", "type": "domain", "verdict": "malicious"},
            {"ioc": "bad.com", "type": "domain", "verdict": "suspicious"},
        ]
        report = reporter.build_report(records)
        self.assertEqual(report["summary"]["total_iocs"], 3)
        self.assertEqual(report["summary"]["by_verdict"]["clean"], 1)
        self.assertEqual(report["summary"]["by_verdict"]["malicious"], 1)
        self.assertEqual(report["summary"]["by_verdict"]["suspicious"], 1)
        self.assertEqual(report["summary"]["by_type"]["domain"], 2)
        self.assertEqual(report["summary"]["by_type"]["ip"], 1)
        self.assertIn("generated_at", report)
        self.assertIn("iocs", report)

    def test_metadata_attached(self):
        report = reporter.build_report([], metadata={"source": "auth.log"})
        self.assertEqual(report["metadata"]["source"], "auth.log")


# ── file loading ─────────────────────────────────────────────────────────────

class TestLoadIocsFromFile(unittest.TestCase):

    def _write_temp_json(self, data, tmp_path):
        with open(tmp_path, "w") as f:
            json.dump(data, f)

    def test_flat_list_of_strings(self, tmp_path="/tmp/test_iocs_flat.json"):
        data = ["1.2.3.4", "evil.com", "d41d8cd98f00b204e9800998ecf8427e"]
        self._write_temp_json(data, tmp_path)
        result = load_iocs_from_file(tmp_path)
        self.assertEqual(result, data)

    def test_iocs_only_format(self, tmp_path="/tmp/test_iocs_only.json"):
        data = {"iocs": ["1.2.3.4", "evil.com"]}
        self._write_temp_json(data, tmp_path)
        result = load_iocs_from_file(tmp_path)
        self.assertEqual(result, ["1.2.3.4", "evil.com"])

    def test_log_normalizer_full_format(self, tmp_path="/tmp/test_lognorm.json"):
        data = {
            "results": [
                {"iocs": ["1.2.3.4"]},
                {"iocs": ["evil.com", "bad.io"]},
            ]
        }
        self._write_temp_json(data, tmp_path)
        result = load_iocs_from_file(tmp_path)
        self.assertIn("1.2.3.4", result)
        self.assertIn("evil.com", result)
        self.assertIn("bad.io", result)


# ── rate limiter ─────────────────────────────────────────────────────────────

class TestRateLimiter(unittest.TestCase):

    def setUp(self):
        # reset rate limiter state before each test
        vt._request_timestamps.clear()

    def test_under_limit_no_sleep(self):
        # 3 requests under the 4/min limit should not sleep
        import time
        start = time.time()
        for _ in range(3):
            vt._rate_limit()
        elapsed = time.time() - start
        self.assertLess(elapsed, 1.0)  # should be near-instant

    def test_rate_limit_state_tracked(self):
        for _ in range(3):
            vt._rate_limit()
        self.assertEqual(len(vt._request_timestamps), 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
