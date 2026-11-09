"""Render inspection and comparison results as rich tables in the terminal."""

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from imagex.vulns import SEVERITY_ORDER, highest_severity, severity_counts, unique_cves

console = Console()

SEVERITY_STYLES = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "UNKNOWN": "dim",
}
INSTRUCTION_WIDTH = 90


def format_size(num_bytes: int) -> str:
    """Human readable size, e.g. 1048576 -> '1.0 MB'."""
    size = float(num_bytes)
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024 or unit == "GB":
            if unit == "B":
                return f"{int(size)} B"
            return f"{size:.1f} {unit}"
        size = size / 1024
    return f"{size:.1f} GB"


def truncate(text: str, width: int) -> str:
    """Shorten text to 'width' characters, marking the cut with '...'."""
    if len(text) <= width:
        return text
    return text[: width - 3] + "..."


def cve_count(image: dict) -> int:
    """Number of unique CVEs in the image."""
    return len(unique_cves(image["packages"]))


def print_warnings(image: dict) -> None:
    """Show anything that went wrong but did not stop the run."""
    for warning in image["warnings"]:
        console.print(f"[yellow]warning:[/yellow] {warning}")


def print_summary(image: dict) -> None:
    """Image name, distro, total size, layer and package counts."""
    table = Table(title=f"Image: {escape(image['name'])}", show_header=False, title_justify="left")
    table.add_column("field", style="bold")
    table.add_column("value")

    table.add_row("Distro", escape(image["distro"]["pretty_name"]))
    table.add_row("OSV ecosystem", image["distro"]["ecosystem"])
    table.add_row("Total size", format_size(image["total_size"]))
    table.add_row("Layers", str(len(image["layers"])))
    table.add_row("Packages", str(len(image["packages"])))
    if image["vulns_checked"]:
        table.add_row("Unique CVEs", str(cve_count(image)))
    console.print(table)


def print_layers(image: dict) -> None:
    """Layers sorted by size, largest first, with the instruction that made each."""
    table = Table(title="Layers (largest first)", title_justify="left")
    table.add_column("#", justify="right")
    table.add_column("Size", justify="right")
    table.add_column("% of image", justify="right")
    table.add_column("Packages added", justify="right")
    table.add_column("Dockerfile instruction", overflow="fold")

    added = {}
    for package in image["packages"]:
        added[package["layer"]] = added.get(package["layer"], 0) + 1

    total = image["total_size"] or 1
    layers = sorted(image["layers"], key=lambda layer: layer["size"], reverse=True)
    for layer in layers:
        percent = 100 * layer["size"] / total
        table.add_row(
            str(layer["index"]),
            format_size(layer["size"]),
            f"{percent:.1f}%",
            str(added.get(layer["index"], 0)),
            escape(truncate(layer["instruction"], INSTRUCTION_WIDTH)),
        )
    console.print(table)


def print_packages(image: dict, show_all: bool) -> None:
    """Packages table. Without --all, only vulnerable packages are listed."""
    packages = image["packages"]
    vulns_checked = image["vulns_checked"]

    # Without a vulnerability lookup there is nothing to filter on.
    if vulns_checked and not show_all:
        packages = [package for package in packages if package["vulns"]]
        title = f"Vulnerable packages ({len(packages)} of {len(image['packages'])}, use --all to list every package)"
    else:
        title = f"Packages ({len(packages)})"

    if vulns_checked:
        packages = sorted(packages, key=lambda package: len(package["vulns"]), reverse=True)

    table = Table(title=title, title_justify="left")
    table.add_column("Name")
    table.add_column("Version")
    table.add_column("Layer", justify="right")
    if vulns_checked:
        table.add_column("CVEs", justify="right")
        table.add_column("Worst", justify="left")

    for package in packages:
        layer = "?" if package["layer"] is None else str(package["layer"])
        # Names and versions come from files inside the image. Escape them
        # so a value like '[red]' is printed literally, not as rich markup.
        row = [escape(package["name"]), escape(package["version"]), layer]
        if vulns_checked:
            if package["vulns"]:
                worst = highest_severity(package["vulns"])
                style = SEVERITY_STYLES[worst]
                row.append(f"[{style}]{len(package['vulns'])}[/{style}]")
                row.append(f"[{style}]{worst.lower()}[/{style}]")
            else:
                row.append("0")
                row.append("")
        table.add_row(*row)

    console.print(table)


def severity_line(image: dict) -> str:
    """'CVEs: 1 critical, 17 high, ... (85 unique)' with colours."""
    counts = severity_counts(image["packages"])
    parts = []
    for severity in SEVERITY_ORDER:
        style = SEVERITY_STYLES[severity]
        parts.append(f"[{style}]{counts[severity]} {severity.lower()}[/{style}]")
    return f"CVEs: {', '.join(parts)}  ({cve_count(image)} unique)"


def print_inspect(image: dict, show_all: bool) -> None:
    """Full terminal report for one image."""
    print_warnings(image)
    print_summary(image)
    print_layers(image)
    print_packages(image, show_all)
    if image["vulns_checked"]:
        console.print(severity_line(image))
    else:
        console.print("[dim]Vulnerability lookup skipped (--no-vulns).[/dim]")


def package_names(image: dict) -> set[str]:
    """Set of binary package names in an image."""
    return {package["name"] for package in image["packages"]}


def print_compare(first: dict, second: dict) -> None:
    """Side by side metrics, then packages that exist in only one image."""
    print_warnings(first)
    print_warnings(second)

    table = Table(title="Comparison", title_justify="left")
    table.add_column("Metric", style="bold")
    table.add_column(escape(first["name"]), justify="right")
    table.add_column(escape(second["name"]), justify="right")

    table.add_row("Distro", escape(first["distro"]["pretty_name"]), escape(second["distro"]["pretty_name"]))
    table.add_row("Total size", format_size(first["total_size"]), format_size(second["total_size"]))
    table.add_row("Layers", str(len(first["layers"])), str(len(second["layers"])))
    table.add_row("Packages", str(len(first["packages"])), str(len(second["packages"])))
    if first["vulns_checked"] and second["vulns_checked"]:
        table.add_row("Unique CVEs", str(cve_count(first)), str(cve_count(second)))
        first_counts = severity_counts(first["packages"])
        second_counts = severity_counts(second["packages"])
        for severity in SEVERITY_ORDER:
            style = SEVERITY_STYLES[severity]
            table.add_row(
                f"  [{style}]{severity.lower()}[/{style}]",
                str(first_counts[severity]),
                str(second_counts[severity]),
            )
    console.print(table)

    first_names = package_names(first)
    second_names = package_names(second)
    print_name_list(f"Only in {first['name']}", sorted(first_names - second_names))
    print_name_list(f"Only in {second['name']}", sorted(second_names - first_names))


def print_name_list(title: str, names: list[str]) -> None:
    """Print a list of package names, wrapped to the terminal width."""
    console.print(f"\n[bold]{escape(title)}[/bold] ({len(names)})")
    if names:
        console.print(escape(", ".join(names)))
    else:
        console.print("[dim]none[/dim]")
