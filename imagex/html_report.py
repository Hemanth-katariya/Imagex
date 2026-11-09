"""Write inspect/compare results as one self-contained HTML file.

No templating library and nothing external: the CSS is in one <style>
block and the only script is a few lines that filter a table, so the
file opens correctly with no network connection.

Every value that comes from the image (package names, versions,
Dockerfile instructions, the image name) goes through esc() first,
because a crafted image could otherwise inject HTML into the report.
"""

import html
from datetime import datetime, timezone

from imagex import __version__
from imagex.report import format_size
from imagex.vulns import SEVERITY_ORDER, highest_severity, severity_counts, unique_cves

# Long RUN instructions are shown shortened, with the full text in a
# <details> element so nothing is lost.
INSTRUCTION_PREVIEW = 140

STYLE = """
:root {
  --text: #1f2328; --muted: #656d76; --border: #d8dee4; --bg: #ffffff;
  --panel: #f6f8fa; --bar: #8c959f;
  --critical: #a40e26; --high: #c4320a; --medium: #9a6700; --low: #3b5bab; --unknown: #6e7781;
}
@media (prefers-color-scheme: dark) {
  :root {
    --text: #e6edf3; --muted: #9198a1; --border: #30363d; --bg: #0d1117;
    --panel: #161b22; --bar: #6e7681;
    --critical: #ff7b72; --high: #ffa657; --medium: #d29922; --low: #79c0ff; --unknown: #8b949e;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0 auto; padding: 32px 20px 64px; max-width: 1120px;
  font-family: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  font-size: 14px; line-height: 1.5; color: var(--text); background: var(--bg);
}
h1 { font-size: 20px; margin: 0 0 4px; }
h2 { font-size: 16px; margin: 40px 0 12px; padding-bottom: 6px; border-bottom: 1px solid var(--border); }
h3 { font-size: 14px; margin: 20px 0 8px; }
p.meta { color: var(--muted); margin: 0 0 20px; }
code, .mono { font-family: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace; font-size: 12px; }
.metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; }
.metric { background: var(--panel); border: 1px solid var(--border); border-radius: 6px; padding: 10px 12px; }
.metric .label { color: var(--muted); font-size: 12px; }
.metric .value { font-size: 18px; font-weight: 600; font-variant-numeric: tabular-nums; }
.severities { margin-top: 12px; display: flex; flex-wrap: wrap; gap: 16px; }
table { border-collapse: collapse; width: 100%; }
th, td { text-align: left; vertical-align: top; padding: 6px 10px; border-bottom: 1px solid var(--border); }
th { color: var(--muted); font-weight: 600; font-size: 12px; white-space: nowrap; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }
.bar-cell { width: 22%; min-width: 120px; }
.bar-track { background: var(--panel); border: 1px solid var(--border); height: 12px; border-radius: 2px; margin-top: 4px; }
.bar { background: var(--bar); height: 100%; }
details summary { cursor: pointer; }
details pre { white-space: pre-wrap; word-break: break-word; margin: 6px 0 0; }
.cves { line-height: 1.8; }
.cves span { margin-right: 10px; white-space: nowrap; }
.sev-critical { color: var(--critical); font-weight: 600; }
.sev-high { color: var(--high); font-weight: 600; }
.sev-medium { color: var(--medium); }
.sev-low { color: var(--low); }
.sev-unknown { color: var(--unknown); }
.muted { color: var(--muted); }
input[type=search] {
  font: inherit; padding: 5px 8px; width: 260px; margin-bottom: 10px;
  border: 1px solid var(--border); border-radius: 4px; background: var(--bg); color: var(--text);
}
.columns { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }
.columns .metrics { grid-template-columns: 1fr 1fr; }
.name-list { columns: 3 180px; column-gap: 20px; margin: 0; padding-left: 18px; }
@media (max-width: 720px) { .columns { grid-template-columns: 1fr; } }
"""

FILTER_SCRIPT = """
document.querySelectorAll("input[data-filter]").forEach(function (input) {
  input.addEventListener("input", function () {
    var query = input.value.toLowerCase();
    var rows = document.querySelectorAll("#" + input.dataset.filter + " tbody tr");
    rows.forEach(function (row) {
      row.style.display = row.dataset.name.indexOf(query) === -1 ? "none" : "";
    });
  });
});
"""


def esc(value: object) -> str:
    """Escape any value for safe use in HTML text and attributes."""
    return html.escape(str(value), quote=True)


def severity_class(severity: str) -> str:
    """CSS class for a severity, e.g. 'HIGH' -> 'sev-high'."""
    return "sev-" + severity.lower()


def page(title: str, body: str) -> str:
    """Wrap body HTML in a complete document with the inline stylesheet."""
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)}</title>
<style>{STYLE}</style>
</head>
<body>
{body}
<p class="meta" style="margin-top:48px">Generated by imagex {esc(__version__)} on {esc(generated)}.
Vulnerability data from OSV (osv.dev).</p>
<script>{FILTER_SCRIPT}</script>
</body>
</html>
"""


def metric(label: str, value: str) -> str:
    """One labelled number box. 'value' is escaped here."""
    return f'<div class="metric"><div class="label">{esc(label)}</div><div class="value">{esc(value)}</div></div>'


def cve_total_text(image: dict) -> str:
    """CVE count as text, or a note when the lookup was skipped."""
    if not image["vulns_checked"]:
        return "not checked"
    return str(len(unique_cves(image["packages"])))


def metrics_grid(image: dict) -> str:
    """The summary boxes shown at the top of a report."""
    boxes = [
        metric("Distro", image["distro"]["pretty_name"]),
        metric("Total size", format_size(image["total_size"])),
        metric("Layers", str(len(image["layers"]))),
        metric("Packages", str(len(image["packages"]))),
        metric("Unique CVEs", cve_total_text(image)),
    ]
    return '<div class="metrics">' + "".join(boxes) + "</div>"


def severity_summary(image: dict) -> str:
    """'1 critical  17 high  ...' coloured by severity."""
    if not image["vulns_checked"]:
        return '<p class="muted">Vulnerability lookup was skipped (--no-vulns).</p>'

    counts = severity_counts(image["packages"])
    parts = []
    for severity in SEVERITY_ORDER:
        # A zero count is not a warning, so it is not coloured.
        css_class = severity_class(severity) if counts[severity] > 0 else "muted"
        parts.append(f'<span class="{css_class}">{counts[severity]} {severity.lower()}</span>')
    return '<div class="severities">' + "".join(parts) + "</div>"


def instruction_cell(instruction: str) -> str:
    """Short instructions as code; long ones collapsible with the full text."""
    if len(instruction) <= INSTRUCTION_PREVIEW:
        return f"<code>{esc(instruction)}</code>"
    preview = instruction[:INSTRUCTION_PREVIEW] + "..."
    return (
        f"<details><summary><code>{esc(preview)}</code></summary>"
        f"<pre class=\"mono\">{esc(instruction)}</pre></details>"
    )


def layers_table(image: dict) -> str:
    """Layer breakdown, largest first, with a bar sized by share of the image."""
    added = {}
    for package in image["packages"]:
        added[package["layer"]] = added.get(package["layer"], 0) + 1

    total = image["total_size"] or 1
    rows = []
    for layer in sorted(image["layers"], key=lambda layer: layer["size"], reverse=True):
        percent = 100 * layer["size"] / total
        rows.append(f"""<tr>
  <td class="num">{layer['index']}</td>
  <td class="num">{esc(format_size(layer['size']))}</td>
  <td class="bar-cell"><span class="muted">{percent:.1f}%</span>
    <div class="bar-track"><div class="bar" style="width:{percent:.2f}%"></div></div></td>
  <td class="num">{added.get(layer['index'], 0)}</td>
  <td>{instruction_cell(layer['instruction'])}</td>
</tr>""")

    return f"""<table>
<thead><tr><th class="num">#</th><th class="num">Size</th><th>Share of image</th>
<th class="num">Packages added</th><th>Dockerfile instruction</th></tr></thead>
<tbody>
{"".join(rows)}
</tbody>
</table>"""


def cve_list(vulns: list[dict]) -> str:
    """CVE ids, each coloured by its own severity, worst first."""
    ordered = sorted(vulns, key=lambda vuln: (SEVERITY_ORDER.index(vuln["severity"]), vuln["cve"]))
    spans = []
    for vuln in ordered:
        spans.append(
            f'<span class="mono {severity_class(vuln["severity"])}" '
            f'title="{esc(vuln["severity"].lower())}">{esc(vuln["cve"])}</span>'
        )
    # Join with spaces so the browser can wrap between ids.
    return '<div class="cves">' + " ".join(spans) + "</div>"


def vulns_table(image: dict, table_id: str) -> str:
    """Vulnerable packages sorted by CVE count, with a name filter box."""
    if not image["vulns_checked"]:
        return '<p class="muted">Vulnerability lookup was skipped (--no-vulns).</p>'

    vulnerable = [package for package in image["packages"] if package["vulns"]]
    if not vulnerable:
        return '<p class="muted">No known vulnerabilities found in OSV for these package versions.</p>'

    vulnerable.sort(key=lambda package: (-len(package["vulns"]), package["name"]))

    rows = []
    for package in vulnerable:
        worst = highest_severity(package["vulns"])
        rows.append(f"""<tr data-name="{esc(package['name'].lower())}">
  <td>{esc(package['name'])}</td>
  <td class="mono">{esc(package['version'])}</td>
  <td class="num {severity_class(worst)}">{len(package['vulns'])}</td>
  <td>{cve_list(package['vulns'])}</td>
</tr>""")

    return f"""<p class="muted">{len(vulnerable)} of {len(image['packages'])} packages have known vulnerabilities.
CVE counts are coloured by the worst severity in that package.</p>
<input type="search" placeholder="Filter by package name" data-filter="{esc(table_id)}">
<table id="{esc(table_id)}">
<thead><tr><th>Package</th><th>Version</th><th class="num">CVEs</th><th>CVE ids</th></tr></thead>
<tbody>
{"".join(rows)}
</tbody>
</table>"""


def warnings_block(image: dict) -> str:
    """Show any non-fatal problems so the report is honest about gaps."""
    if not image["warnings"]:
        return ""
    items = "".join(f"<li>{esc(warning)}</li>" for warning in image["warnings"])
    return f'<ul class="muted">{items}</ul>'


def render_inspect(image: dict) -> str:
    """Full HTML document for one image."""
    body = f"""
<h1>{esc(image['name'])}</h1>
<p class="meta">imagex inspect &middot; OSV ecosystem <code>{esc(image['distro']['ecosystem'])}</code></p>
{warnings_block(image)}
{metrics_grid(image)}
{severity_summary(image)}

<h2>Layer breakdown</h2>
{layers_table(image)}

<h2>Vulnerable packages</h2>
{vulns_table(image, "vulns")}
"""
    return page(f"imagex: {image['name']}", body)


def name_list(names: list[str]) -> str:
    """A multi-column bullet list of package names."""
    if not names:
        return '<p class="muted">none</p>'
    items = "".join(f"<li class=\"mono\">{esc(name)}</li>" for name in names)
    return f'<ul class="name-list">{items}</ul>'


def compare_column(image: dict) -> str:
    """One side of the comparison: the same metrics as an inspect report."""
    return f"""<div>
<h3>{esc(image['name'])}</h3>
{metrics_grid(image)}
{severity_summary(image)}
</div>"""


def render_compare(first: dict, second: dict) -> str:
    """Full HTML document comparing two images."""
    first_names = {package["name"] for package in first["packages"]}
    second_names = {package["name"] for package in second["packages"]}
    only_first = sorted(first_names - second_names)
    only_second = sorted(second_names - first_names)

    body = f"""
<h1>{esc(first['name'])} vs {esc(second['name'])}</h1>
<p class="meta">imagex compare</p>
{warnings_block(first)}
{warnings_block(second)}

<h2>Summary</h2>
<div class="columns">
{compare_column(first)}
{compare_column(second)}
</div>

<h2>Packages in only one image</h2>
<div class="columns">
<div><h3>Only in {esc(first['name'])} ({len(only_first)})</h3>{name_list(only_first)}</div>
<div><h3>Only in {esc(second['name'])} ({len(only_second)})</h3>{name_list(only_second)}</div>
</div>
<p class="muted">{len(first_names & second_names)} package names are present in both images.</p>
"""
    return page(f"imagex: {first['name']} vs {second['name']}", body)


def write_file(path: str, text: str) -> None:
    """Write the report as UTF-8."""
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def write_inspect_report(image: dict, path: str) -> None:
    """Write the HTML report for `imagex inspect --html`."""
    write_file(path, render_inspect(image))


def write_compare_report(first: dict, second: dict, path: str) -> None:
    """Write the HTML report for `imagex compare --html`."""
    write_file(path, render_compare(first, second))
