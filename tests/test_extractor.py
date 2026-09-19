"""
Unit tests for the IOC extractor module.
"""

import json
import tempfile
import os
import sys

# Add the parent directory to the sys.path so we can import ioc_extractor
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ioc_extractor import extract_iocs, extract_from_file, count_iocs


def test_extract_ipv4():
    text = "Malicious IP: 185.220.101.5 and internal IP: 10.0.0.1"
    result = extract_iocs(text)
    assert "185.220.101.5" in result["ipv4"]
    assert "10.0.0.1" not in result["ipv4"]  # filtered as private
    # When not filtering
    result_no_filter = extract_iocs(text, filter_private=False)
    assert "10.0.0.1" in result_no_filter["ipv4"]


def test_extract_ipv6():
    text = "IPv6 address: 2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    result = extract_iocs(text)
    assert "2001:0db8:85a3:0000:0000:8a2e:0370:7334" in result["ipv6"]


def test_extract_hashes():
    text = (
        "MD5: 44d88612fea8a8f36de82e1278abb02f "
        "SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709 "
        "SHA256: 3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b"
    )
    result = extract_iocs(text)
    assert result["md5"] == ["44d88612fea8a8f36de82e1278abb02f"]
    assert result["sha1"] == ["da39a3ee5e6b4b0d3255bfef95601890afd80709"]
    assert result["sha256"] == ["3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b"]


def test_extract_url_and_domain():
    text = "Visit http://evil.com/path?query=1 for more info. Also see evil.com"
    result = extract_iocs(text)
    # URL should be extracted
    assert "http://evil.com/path?query=1" in result["url"]
    # Domain should be extracted once (deduplicated)
    assert result["domain"] == ["evil.com"]


def test_extract_email():
    text = "Contact: admin@evil.com and support@evil.com"
    result = extract_iocs(text)
    assert set(result["email"]) == {"admin@evil.com", "support@evil.com"}


def test_deduplication():
    text = "IP 1.2.3.4 appears again 1.2.3.4 and hash abcdef1234567890abcdef1234567890 abcdef1234567890abcdef1234567890"
    result = extract_iocs(text)
    assert len(result["ipv4"]) == 1
    assert len(result["md5"]) == 1


def test_extract_from_file():
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as f:
        f.write("Test IP: 8.8.8.8\n")
        temp_path = f.name

    try:
        result = extract_from_file(temp_path)
        assert result["ipv4"] == ["8.8.8.8"]
    finally:
        os.unlink(temp_path)


def test_count_iocs():
    extracted = {
        "ipv4": ["8.8.8.8", "8.8.4.4"],
        "domain": ["google.com"],
        "md5": ["44d88612fea8a8f36de82e1278abb02f"],
    }
    assert count_iocs(extracted) == 4


# Allow running the test file directly (without pytest)
if __name__ == '__main__':
    # List of test functions
    tests = [
        test_extract_ipv4,
        test_extract_ipv6,
        test_extract_hashes,
        test_extract_url_and_domain,
        test_extract_email,
        test_deduplication,
        test_extract_from_file,
        test_count_iocs,
    ]

    failed = 0
    for test in tests:
        try:
            test()
            print(f"PASS: {test.__name__}")
        except AssertionError as e:
            print(f"FAIL: {test.__name__} -> {e}")
            failed += 1
        except Exception as e:
            print(f"ERROR: {test.__name__} -> {e}")
            failed += 1

    if failed == 0:
        print(f"All {len(tests)} tests passed.")
        sys.exit(0)
    else:
        print(f"{failed} out of {len(tests)} tests failed.")
        sys.exit(1)