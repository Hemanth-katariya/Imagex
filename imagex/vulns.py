"""Look up known vulnerabilities for packages using the OSV API.

Two steps:
  1. POST all packages to /v1/querybatch (100 per request). This returns
     only the vulnerability ids affecting each package version.
  2. GET /v1/vulns/<id> for each unique id to read its CVE id and CVSS
     severity vector.

Network problems never crash the tool; they are reported as warnings
and the affected packages simply show no vulnerabilities.
"""

import math
from concurrent.futures import ThreadPoolExecutor

import requests

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
BATCH_SIZE = 100
TIMEOUT_SECONDS = 30
# Detail lookups are independent HTTP GETs, so a few run in parallel.
# Without this, an image with ~1000 advisories takes minutes.
DETAIL_WORKERS = 8

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]

# CVSS 3.x base metric weights, from the CVSS v3.1 specification, section 7.4.
CVSS_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
# Privileges Required weighs differently when the scope changes.
CVSS_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
CVSS_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}


def query_key(package: dict) -> tuple[str, str]:
    """The (source name, source version) pair we ask OSV about.

    OSV indexes Debian and Alpine advisories by *source* package, so the
    binary 'libssl3' only matches when we ask about its source 'openssl'.
    """
    return (package["source"], package["source_version"])


def roundup(value: float) -> float:
    """CVSS 3.1 'Roundup': round up to one decimal, avoiding float noise."""
    as_int = round(value * 100000)
    if as_int % 10000 == 0:
        return as_int / 100000.0
    return (math.floor(as_int / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> float | None:
    """Compute the CVSS 3.x base score from a vector string.

    Example vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' -> 9.8
    Returns None if the vector is not a valid CVSS 3 vector.
    """
    if not vector.startswith("CVSS:3"):
        return None

    metrics = {}
    for part in vector.split("/")[1:]:
        if ":" in part:
            key, value = part.split(":", 1)
            metrics[key] = value

    try:
        scope_changed = metrics["S"] == "C"
        av = CVSS_WEIGHTS["AV"][metrics["AV"]]
        ac = CVSS_WEIGHTS["AC"][metrics["AC"]]
        ui = CVSS_WEIGHTS["UI"][metrics["UI"]]
        c = CVSS_WEIGHTS["C"][metrics["C"]]
        i = CVSS_WEIGHTS["I"][metrics["I"]]
        a = CVSS_WEIGHTS["A"][metrics["A"]]
        if scope_changed:
            pr = CVSS_PR_CHANGED[metrics["PR"]]
        else:
            pr = CVSS_PR_UNCHANGED[metrics["PR"]]
    except KeyError:
        return None

    impact_sub_score = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (impact_sub_score - 0.029) - 3.25 * (impact_sub_score - 0.02) ** 15
    else:
        impact = 6.42 * impact_sub_score
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0
    if scope_changed:
        return roundup(min(1.08 * (impact + exploitability), 10))
    return roundup(min(impact + exploitability, 10))


def score_to_severity(score: float) -> str:
    """Map a CVSS score to its qualitative rating."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "UNKNOWN"


def severity_of(vuln: dict) -> str:
    """Pick a severity for an OSV record.

    Prefers a CVSS v3 vector. Some sources (for example GitHub advisories)
    instead put a word like 'HIGH' in database_specific.severity.
    """
    for entry in vuln.get("severity", []):
        if entry.get("type") == "CVSS_V3":
            score = cvss3_base_score(entry.get("score", ""))
            if score is not None:
                return score_to_severity(score)

    word = str((vuln.get("database_specific") or {}).get("severity", "")).upper()
    if word == "MODERATE":
        word = "MEDIUM"
    if word in SEVERITY_ORDER:
        return word
    return "UNKNOWN"


def cve_id_of(vuln: dict) -> str:
    """Return the CVE id for an OSV record, or its own id if it has none.

    Distro records have ids like 'DEBIAN-CVE-2024-0727' and list the real
    CVE in 'upstream' or 'aliases'.
    """
    vuln_id = vuln.get("id", "")
    if vuln_id.startswith("CVE-"):
        return vuln_id

    related = (vuln.get("upstream") or []) + (vuln.get("aliases") or [])
    for other_id in related:
        if other_id.startswith("CVE-"):
            return other_id
    return vuln_id


def query_batch(
    session: requests.Session,
    ecosystem: str,
    keys: list[tuple[str, str]],
    page_tokens: dict,
) -> list[tuple[list[str], str | None]]:
    """Ask OSV which vulnerability ids affect each (name, version) pair.

    OSV returns at most 1000 ids per package per request. If there are
    more, the result carries a 'next_page_token' that we send back to get
    the next page. 'page_tokens' holds the token for each key, if any.

    Returns one (ids, next_page_token) pair per key, in the order of 'keys'.
    """
    queries = []
    for key in keys:
        name, version = key
        query = {
            "package": {"name": name, "ecosystem": ecosystem},
            "version": version,
        }
        if page_tokens.get(key):
            query["page_token"] = page_tokens[key]
        queries.append(query)

    response = session.post(OSV_BATCH_URL, json={"queries": queries}, timeout=TIMEOUT_SECONDS)
    response.raise_for_status()
    results = response.json().get("results", [])

    pairs = []
    for result in results:
        ids = [vuln["id"] for vuln in result.get("vulns", [])]
        pairs.append((ids, result.get("next_page_token")))
    return pairs


def query_all_pages(session: requests.Session, ecosystem: str, keys: list[tuple[str, str]]) -> dict:
    """Run query_batch for one batch of keys, following page tokens.

    Usually one request is enough. A package with a huge advisory history
    (linux-libc-dev has thousands of kernel CVEs) needs several pages.
    """
    ids_by_key = {key: [] for key in keys}
    page_tokens = {}
    pending = list(keys)

    while pending:
        results = query_batch(session, ecosystem, pending, page_tokens)
        still_pending = []
        for key, (ids, next_token) in zip(pending, results):
            ids_by_key[key].extend(ids)
            if next_token:
                page_tokens[key] = next_token
                still_pending.append(key)
        pending = still_pending

    return ids_by_key


def fetch_details(session: requests.Session, vuln_id: str) -> dict:
    """Fetch one OSV record and reduce it to the fields we report.

    On a network error we still return a usable record, just with an
    unknown severity, so one failed request does not hide the finding.
    """
    try:
        response = session.get(OSV_VULN_URL + vuln_id, timeout=TIMEOUT_SECONDS)
        response.raise_for_status()
        vuln = response.json()
    except (requests.RequestException, ValueError):
        return {"id": vuln_id, "cve": vuln_id, "severity": "UNKNOWN", "fetched": False}

    return {
        "id": vuln_id,
        "cve": cve_id_of(vuln),
        "severity": severity_of(vuln),
        "fetched": True,
    }


def find_vulns(packages: list[dict], ecosystem: str) -> tuple[dict, list[str]]:
    """Look up vulnerabilities for all packages.

    Returns:
      - a dict mapping query_key(package) -> list of vulnerability records
      - a list of warning messages (empty if everything worked)
    """
    warnings = []

    # Many binary packages share one source package; ask about each once.
    unique_keys = sorted({query_key(package) for package in packages})

    ids_by_key = {}
    with requests.Session() as session:
        for start in range(0, len(unique_keys), BATCH_SIZE):
            batch = unique_keys[start:start + BATCH_SIZE]
            try:
                ids_by_key.update(query_all_pages(session, ecosystem, batch))
            except (requests.RequestException, ValueError) as error:
                warnings.append(f"OSV batch query failed ({len(batch)} packages skipped): {error}")

        all_ids = set()
        for ids in ids_by_key.values():
            all_ids.update(ids)

        details_by_id = {}
        with ThreadPoolExecutor(max_workers=DETAIL_WORKERS) as pool:
            for record in pool.map(lambda vuln_id: fetch_details(session, vuln_id), sorted(all_ids)):
                details_by_id[record["id"]] = record

    failed = [record for record in details_by_id.values() if not record["fetched"]]
    if failed:
        warnings.append(f"could not fetch details for {len(failed)} vulnerabilities; severity shown as UNKNOWN")

    # Keep one record per CVE for each package, in case two OSV records
    # (for example a DSA and a DEBIAN-CVE entry) describe the same CVE.
    vulns_by_key = {}
    for key, ids in ids_by_key.items():
        records = []
        seen_cves = set()
        for vuln_id in ids:
            record = details_by_id[vuln_id]
            if record["cve"] not in seen_cves:
                seen_cves.add(record["cve"])
                records.append(record)
        vulns_by_key[key] = records
    return vulns_by_key, warnings


def unique_cves(packages: list[dict]) -> dict[str, str]:
    """Return {cve_id: severity} across the whole image.

    The same CVE often shows up on several binary packages built from one
    source (libssl3 and openssl), so we count each CVE once per image.
    """
    cves = {}
    for package in packages:
        for vuln in package.get("vulns", []):
            cves[vuln["cve"]] = vuln["severity"]
    return cves


def severity_counts(packages: list[dict]) -> dict[str, int]:
    """Count unique CVEs per severity, in a fixed severity order."""
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for severity in unique_cves(packages).values():
        counts[severity] += 1
    return counts


def highest_severity(vulns: list[dict]) -> str:
    """The worst severity in a list of vulnerability records."""
    for severity in SEVERITY_ORDER:
        for vuln in vulns:
            if vuln["severity"] == severity:
                return severity
    return "UNKNOWN"
