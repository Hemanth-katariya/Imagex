"""Parse the OS package databases found inside an image.

Debian/Ubuntu keep installed packages in /var/lib/dpkg/status.
Alpine keeps them in /lib/apk/db/installed.
Both are plain text made of blank-line separated "stanzas", one per
package, so they share one small stanza parser.
"""

import os
import re

DPKG_STATUS = "var/lib/dpkg/status"
APK_INSTALLED = "lib/apk/db/installed"

# "Source: gcc-12 (12.2.0-14)" -> name "gcc-12", version "12.2.0-14"
SOURCE_FIELD = re.compile(r"^(\S+)(?:\s+\((.+)\))?$")


def parse_stanzas(text: str) -> list[dict]:
    """Split 'Key: value' text into one dict per blank-line separated block.

    Lines starting with a space or tab continue the previous field (dpkg
    uses this for multi-line descriptions). We append them so that a
    continuation line is never mistaken for a new key.
    """
    stanzas = []
    current = {}
    last_key = None

    for line in text.splitlines():
        if line.strip() == "":
            if current:
                stanzas.append(current)
            current = {}
            last_key = None
            continue

        if line[0] in " \t":
            if last_key is not None:
                current[last_key] += "\n" + line.strip()
            continue

        if ":" not in line:
            continue  # malformed line; ignore it rather than fail

        key, value = line.split(":", 1)
        last_key = key.strip()
        current[last_key] = value.strip()

    if current:
        stanzas.append(current)
    return stanzas


def parse_dpkg_status(text: str) -> list[dict]:
    """Parse /var/lib/dpkg/status into package dicts.

    Only packages whose Status ends in 'installed' are kept. dpkg also
    lists removed packages that left config files behind
    ('deinstall ok config-files'), and those are not really installed.

    'source' is the Debian source package (e.g. libssl3 is built from
    openssl). Vulnerability databases are keyed by source package, so we
    keep it alongside the binary package name.
    """
    packages = []
    for stanza in parse_stanzas(text):
        name = stanza.get("Package")
        version = stanza.get("Version")
        if not name or not version:
            continue

        status = stanza.get("Status", "install ok installed")
        if status.split()[-1] != "installed":
            continue

        source = name
        source_version = version
        if "Source" in stanza:
            match = SOURCE_FIELD.match(stanza["Source"])
            if match:
                source = match.group(1)
                if match.group(2):
                    source_version = match.group(2)

        packages.append({
            "name": name,
            "version": version,
            "architecture": stanza.get("Architecture", ""),
            "source": source,
            "source_version": source_version,
        })
    return packages


def parse_apk_installed(text: str) -> list[dict]:
    """Parse /lib/apk/db/installed into package dicts.

    Keys are single letters: P = package name, V = version,
    A = architecture, o = origin (the source package it was built from).
    """
    packages = []
    for stanza in parse_stanzas(text):
        name = stanza.get("P")
        version = stanza.get("V")
        if not name or not version:
            continue

        packages.append({
            "name": name,
            "version": version,
            "architecture": stanza.get("A", ""),
            "source": stanza.get("o", name),
            "source_version": version,
        })
    return packages


def read_os_release(root: str) -> dict:
    """Read /etc/os-release (or /usr/lib/os-release) into a dict.

    On Debian /etc/os-release is a symlink, and the unpacker skips
    symlinks, so we also try the file it points to.
    """
    for relative in ["etc/os-release", "usr/lib/os-release"]:
        path = os.path.join(root, relative)
        if not os.path.isfile(path):
            continue

        info = {}
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if "=" not in line or line.startswith("#"):
                    continue
                key, value = line.split("=", 1)
                info[key] = value.strip('"').strip("'")
        return info
    return {}


def osv_ecosystem(distro_id: str, os_release: dict) -> str:
    """Build the OSV ecosystem name, including the release.

    OSV records advisories per release ('Debian:12', 'Alpine:v3.20').
    Querying plain 'Debian' matches advisories for every Debian release
    and overcounts, so we add the release whenever we know it.
    """
    version_id = os_release.get("VERSION_ID", "")

    if distro_id == "alpine":
        parts = version_id.split(".")
        if len(parts) >= 2:
            return f"Alpine:v{parts[0]}.{parts[1]}"
        return "Alpine"

    if distro_id == "ubuntu":
        if version_id == "":
            return "Ubuntu"
        if "LTS" in os_release.get("VERSION", ""):
            return f"Ubuntu:{version_id}:LTS"
        return f"Ubuntu:{version_id}"

    # Debian: VERSION_ID is "12"; it is missing on testing/unstable.
    if version_id:
        return f"Debian:{version_id.split('.')[0]}"
    return "Debian"


def detect_distro(root: str) -> dict | None:
    """Work out which package database the image uses.

    Returns None if neither a dpkg nor an apk database exists, which is
    the case for scratch, distroless-static and similar images.
    """
    os_release = read_os_release(root)
    pretty_name = os_release.get("PRETTY_NAME", "")

    if os.path.isfile(os.path.join(root, APK_INSTALLED)):
        return {
            "id": "alpine",
            "pretty_name": pretty_name or "Alpine Linux",
            "db_path": APK_INSTALLED,
            "ecosystem": osv_ecosystem("alpine", os_release),
        }

    if os.path.isfile(os.path.join(root, DPKG_STATUS)):
        distro_id = "ubuntu" if os_release.get("ID") == "ubuntu" else "debian"
        return {
            "id": distro_id,
            "pretty_name": pretty_name or distro_id.capitalize(),
            "db_path": DPKG_STATUS,
            "ecosystem": osv_ecosystem(distro_id, os_release),
        }

    return None


def parse_package_db(distro: dict, text: str) -> list[dict]:
    """Pick the right parser for the detected distro."""
    if distro["id"] == "alpine":
        return parse_apk_installed(text)
    return parse_dpkg_status(text)


def find_package_layers(distro: dict, layers: list[dict]) -> dict:
    """Map (name, version) to the index of the layer that installed it.

    Every layer that installs packages writes a new copy of the package
    database. Walking the layers in order, the first copy that mentions a
    package version tells us which layer added it.
    """
    first_seen = {}
    for layer in layers:
        text = layer["package_dbs"].get(distro["db_path"])
        if text is None:
            continue
        for package in parse_package_db(distro, text):
            key = (package["name"], package["version"])
            if key not in first_seen:
                first_seen[key] = layer["index"]
    return first_seen


def load_packages(root: str, distro: dict, layers: list[dict]) -> list[dict]:
    """Read the final package list and tag each package with its layer.

    Each package is normalised to the same shape for both distros:
    name, version, ecosystem, plus source package and layer index.
    """
    db_file = os.path.join(root, distro["db_path"])
    with open(db_file, encoding="utf-8", errors="replace") as f:
        text = f.read()

    first_seen = find_package_layers(distro, layers)

    packages = []
    for package in parse_package_db(distro, text):
        package["ecosystem"] = distro["ecosystem"]
        package["layer"] = first_seen.get((package["name"], package["version"]))
        packages.append(package)

    packages.sort(key=lambda p: p["name"])
    return packages
