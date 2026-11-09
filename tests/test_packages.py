"""Unit tests for the dpkg and apk parsers, using small hardcoded inputs.

Run with:  python -m unittest discover -s tests
"""

import unittest

from imagex.packages import osv_ecosystem, parse_apk_installed, parse_dpkg_status, parse_stanzas

DPKG_SAMPLE = """\
Package: libssl3t64
Status: install ok installed
Priority: optional
Architecture: amd64
Source: openssl
Version: 3.5.1-1
Description: Secure Sockets Layer toolkit - shared libraries
 This package is part of the OpenSSL project's implementation of the SSL
 and TLS cryptographic protocols.

Package: gcc-14-base
Status: install ok installed
Architecture: amd64
Source: gcc-14 (14.2.0-19)
Version: 14.2.0-19+b1

Package: oldpackage
Status: deinstall ok config-files
Architecture: all
Version: 1.0-1

Package: bash
Status: install ok installed
Architecture: amd64
Version: 5.2.37-2
"""

APK_SAMPLE = """\
C:Q1abcdefghijklmnopqrstuvwxyz=
P:musl
V:1.2.5-r3
A:x86_64
o:musl
F:lib
R:ld-musl-x86_64.so.1

C:Q1zyxwvutsrqponmlkjihgfedcba=
P:libcrypto3
V:3.3.2-r0
A:x86_64
o:openssl

P:busybox
V:1.36.1-r29
A:x86_64
"""


class ParseStanzasTest(unittest.TestCase):
    def test_splits_on_blank_lines(self):
        stanzas = parse_stanzas("A: 1\nB: 2\n\nA: 3\n")
        self.assertEqual(stanzas, [{"A": "1", "B": "2"}, {"A": "3"}])

    def test_continuation_lines_join_previous_field(self):
        stanzas = parse_stanzas("Description: first\n second line\nNext: x\n")
        self.assertEqual(stanzas[0]["Description"], "first\nsecond line")
        self.assertEqual(stanzas[0]["Next"], "x")

    def test_value_may_contain_colons(self):
        stanzas = parse_stanzas("Homepage: https://example.com:8080/x\n")
        self.assertEqual(stanzas[0]["Homepage"], "https://example.com:8080/x")

    def test_empty_input(self):
        self.assertEqual(parse_stanzas(""), [])
        self.assertEqual(parse_stanzas("\n\n\n"), [])


class DpkgParserTest(unittest.TestCase):
    def setUp(self):
        self.packages = parse_dpkg_status(DPKG_SAMPLE)
        self.by_name = {package["name"]: package for package in self.packages}

    def test_reads_installed_packages_only(self):
        self.assertEqual(sorted(self.by_name), ["bash", "gcc-14-base", "libssl3t64"])

    def test_name_version_architecture(self):
        bash = self.by_name["bash"]
        self.assertEqual(bash["version"], "5.2.37-2")
        self.assertEqual(bash["architecture"], "amd64")

    def test_source_defaults_to_package_name(self):
        bash = self.by_name["bash"]
        self.assertEqual(bash["source"], "bash")
        self.assertEqual(bash["source_version"], "5.2.37-2")

    def test_source_field_without_version(self):
        ssl = self.by_name["libssl3t64"]
        self.assertEqual(ssl["source"], "openssl")
        self.assertEqual(ssl["source_version"], "3.5.1-1")

    def test_source_field_with_version(self):
        gcc = self.by_name["gcc-14-base"]
        self.assertEqual(gcc["source"], "gcc-14")
        self.assertEqual(gcc["source_version"], "14.2.0-19")
        self.assertEqual(gcc["version"], "14.2.0-19+b1")

    def test_stanza_without_version_is_skipped(self):
        self.assertEqual(parse_dpkg_status("Package: broken\nStatus: install ok installed\n"), [])


class ApkParserTest(unittest.TestCase):
    def setUp(self):
        self.packages = parse_apk_installed(APK_SAMPLE)
        self.by_name = {package["name"]: package for package in self.packages}

    def test_reads_all_packages(self):
        self.assertEqual(sorted(self.by_name), ["busybox", "libcrypto3", "musl"])

    def test_name_and_version(self):
        self.assertEqual(self.by_name["musl"]["version"], "1.2.5-r3")
        self.assertEqual(self.by_name["musl"]["architecture"], "x86_64")

    def test_origin_is_source_package(self):
        self.assertEqual(self.by_name["libcrypto3"]["source"], "openssl")

    def test_missing_origin_falls_back_to_name(self):
        self.assertEqual(self.by_name["busybox"]["source"], "busybox")


class EcosystemTest(unittest.TestCase):
    def test_debian_uses_major_version(self):
        self.assertEqual(osv_ecosystem("debian", {"VERSION_ID": "12"}), "Debian:12")

    def test_debian_without_version(self):
        self.assertEqual(osv_ecosystem("debian", {}), "Debian")

    def test_alpine_uses_major_minor(self):
        self.assertEqual(osv_ecosystem("alpine", {"VERSION_ID": "3.20.3"}), "Alpine:v3.20")

    def test_ubuntu_lts(self):
        release = {"VERSION_ID": "24.04", "VERSION": "24.04.1 LTS (Noble Numbat)"}
        self.assertEqual(osv_ecosystem("ubuntu", release), "Ubuntu:24.04:LTS")


if __name__ == "__main__":
    unittest.main()
