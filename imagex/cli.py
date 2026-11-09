"""Command line entry point: argument parsing and command dispatch.

  imagex inspect <tarfile> [--no-vulns] [--all] [--sbom out.json] [--html report.html]
  imagex compare <tar1> <tar2> [--no-vulns] [--html out.html]
"""

import argparse
import json
import sys
import tempfile

from rich.markup import escape

from imagex import html_report, report
from imagex.packages import detect_distro, load_packages
from imagex.unpack import ImageError, unpack_image
from imagex.vulns import find_vulns, query_key


def analyse_image(tar_path: str, check_vulns: bool) -> dict:
    """Unpack an image, parse its packages and optionally look up CVEs.

    Returns one dict with everything the terminal and HTML reports need.
    The extracted filesystem lives in a temporary directory that is
    deleted as soon as the packages have been read.
    """
    report.console.print(f"[dim]Unpacking {escape(tar_path)} ...[/dim]")
    with tempfile.TemporaryDirectory(prefix="imagex-", ignore_cleanup_errors=True) as temp_dir:
        image = unpack_image(tar_path, temp_dir)

        distro = detect_distro(image["root"])
        if distro is None:
            raise ImageError(
                f"{tar_path}: no package database found "
                "(looked for /var/lib/dpkg/status and /lib/apk/db/installed). "
                "imagex supports Debian, Ubuntu and Alpine based images."
            )
        packages = load_packages(image["root"], distro, image["layers"])

    warnings = []
    skipped = sum(layer["skipped_files"] for layer in image["layers"])
    if skipped:
        warnings.append(f"{skipped} files could not be written to disk on this OS and were skipped")

    for package in packages:
        package["vulns"] = []

    if check_vulns:
        report.console.print(f"[dim]Querying OSV for {len(packages)} packages ...[/dim]")
        vulns_by_key, vuln_warnings = find_vulns(packages, distro["ecosystem"])
        warnings.extend(vuln_warnings)
        for package in packages:
            package["vulns"] = vulns_by_key.get(query_key(package), [])

    return {
        "name": image["name"],
        "tar_path": tar_path,
        "distro": distro,
        "layers": image["layers"],
        "total_size": image["total_size"],
        "packages": packages,
        "vulns_checked": check_vulns,
        "warnings": warnings,
    }


def write_sbom(image: dict, path: str) -> None:
    """Write the package list as JSON (a minimal software bill of materials)."""
    packages = []
    for package in image["packages"]:
        packages.append({
            "name": package["name"],
            "version": package["version"],
            "ecosystem": package["ecosystem"],
            "architecture": package["architecture"],
            "source": package["source"],
            "source_version": package["source_version"],
            "layer": package["layer"],
            "cves": [vuln["cve"] for vuln in package["vulns"]],
        })

    document = {
        "image": image["name"],
        "distro": image["distro"]["pretty_name"],
        "vulns_checked": image["vulns_checked"],
        "packages": packages,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(document, f, indent=2)
    report.console.print(f"SBOM written to {path}")


def run_inspect(args: argparse.Namespace) -> None:
    """Handle `imagex inspect`."""
    image = analyse_image(args.tarfile, check_vulns=not args.no_vulns)
    report.print_inspect(image, show_all=args.all)

    if args.sbom:
        write_sbom(image, args.sbom)
    if args.html:
        html_report.write_inspect_report(image, args.html)
        report.console.print(f"HTML report written to {args.html}")


def run_compare(args: argparse.Namespace) -> None:
    """Handle `imagex compare`."""
    first = analyse_image(args.tar1, check_vulns=not args.no_vulns)
    second = analyse_image(args.tar2, check_vulns=not args.no_vulns)
    report.print_compare(first, second)

    if args.html:
        html_report.write_compare_report(first, second, args.html)
        report.console.print(f"HTML report written to {args.html}")


def build_parser() -> argparse.ArgumentParser:
    """Define the 'inspect' and 'compare' sub-commands and their flags."""
    parser = argparse.ArgumentParser(
        prog="imagex",
        description="Inspect Docker image tars (from `docker save`) without running them.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    inspect = commands.add_parser("inspect", help="report packages, layers and CVEs for one image")
    inspect.add_argument("tarfile", help="image tar created with `docker save`")
    inspect.add_argument("--no-vulns", action="store_true", help="skip the OSV vulnerability lookup")
    inspect.add_argument("--all", action="store_true", help="list every package, not only vulnerable ones")
    inspect.add_argument("--sbom", metavar="PATH", help="write the package list as JSON")
    inspect.add_argument("--html", metavar="PATH", help="write a self-contained HTML report")
    inspect.set_defaults(handler=run_inspect)

    compare = commands.add_parser("compare", help="diff two images")
    compare.add_argument("tar1", help="first image tar")
    compare.add_argument("tar2", help="second image tar")
    compare.add_argument("--no-vulns", action="store_true", help="skip the OSV vulnerability lookup")
    compare.add_argument("--html", metavar="PATH", help="write a self-contained HTML report")
    compare.set_defaults(handler=run_compare)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Parse arguments and run the chosen command. Returns the exit code."""
    args = build_parser().parse_args(argv)
    try:
        args.handler(args)
    except ImageError as error:
        report.console.print(f"[red]error:[/red] {escape(str(error))}", highlight=False)
        return 1
    except OSError as error:
        report.console.print(f"[red]error:[/red] {escape(str(error))}", highlight=False)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
