#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import json
import requests
import csv
import re
import logging
from packaging import version
from packaging.version import InvalidVersion
from jinja2 import Environment, FileSystemLoader

# ---------------- Configuration ----------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

REQUIREMENTS_FILE = 'requirements_full_list.txt'
OUTPUT_CSV = 'dependency_report.csv'
OUTPUT_HTML = 'dependency_report.html'
PIP_AUDIT_CMD = ['pip-audit', '--format', 'json']
PYPI_URL_TEMPLATE = 'https://pypi.org/pypi/{package}/json'
# ------------------------------------------------

def parse_requirements(requirements_file):
    """Parse requirements.txt into dict {package_name: current_version}"""
    pkgs = {}
    with open(requirements_file, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            name = re.split(r"[<>=!~]+", line)[0].strip()
            m = re.search(r"(==|>=|<=|~=|!=)(.+)", line)
            ver = m.group(2).strip() if m else 'unknown'
            pkgs[name] = ver
    logger.info(f"Parsed {len(pkgs)} packages from {requirements_file}")
    return pkgs

def run_pip_audit():
    """Run pip-audit against requirements.txt, return dict {pkg_lower: "ID - description; ..."}"""
    cmd = ['pip-audit', '--format', 'json', '-r', REQUIREMENTS_FILE]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)
        logger.info("pip-audit scan complete")
    except Exception as e:
        logger.error(f"pip-audit error: {e}")
        return {}
    vuln_map = {}
    for item in data:
        pkg = item.get('name', '').lower()
        details = [f"{v.get('id')} - {v.get('description')}" for v in item.get('vulns', [])]
        vuln_map[pkg] = '; '.join(details)
    return vuln_map

def get_pypi_info(package):
    """Fetch PyPI JSON metadata for a package"""
    url = PYPI_URL_TEMPLATE.format(package=package)
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        logger.warning(f"Fetch PyPI metadata for {package} failed: {e}")
    return None

def suggest_upgrade_version(all_versions, current_version):
    """
    Suggest an upgrade version.
    Prefer latest in same major version if available, else latest overall.
    """
    try:
        cur_ver = version.parse(current_version)
        parsed_versions = []
        for v in all_versions:
            try:
                pv = version.parse(v)
                parsed_versions.append((pv, v))  # keep original string
            except InvalidVersion:
                continue

        # Filter out current and lower versions
        newer_versions = [v for (pv, v) in parsed_versions if pv > cur_ver]
        if not newer_versions:
            return 'Up-to-date'

        # Recommand same major version first
        same_major = [v for (pv, v) in parsed_versions
                      if pv > cur_ver and pv.major == cur_ver.major]
        if same_major:
            return same_major[-1]

        # Else return the newest version
        return newer_versions[-1]

    except Exception as e:
        logger.error(f"Suggest upgrade error for {current_version}: {e}")
        return 'unknown'


def extract_dependencies(info):
    """Extract requires_dist from PyPI metadata"""
    return info.get('info', {}).get('requires_dist') or []

def main():
    pkgs = parse_requirements(REQUIREMENTS_FILE)
    vuln_map = run_pip_audit()
    rows = []

    for idx, (pkg, cur_ver) in enumerate(pkgs.items(), 1):
        logger.info(f"[{idx}/{len(pkgs)}] Processing package: {pkg}, current version: {cur_ver}")

        info = get_pypi_info(pkg)
        if info:
            # Filter out invalid versions before sorting
            raw_versions = info.get('releases', {}).keys()
            valid_versions = []
            for v in raw_versions:
                try:
                    version.parse(v)
                    valid_versions.append(v)
                except InvalidVersion:
                    logger.warning(f"Package {pkg} has invalid version string skipped: {v}")

            all_vs = sorted(valid_versions, key=version.parse)

        else:
            all_vs = []

        try:
            newer = [v for v in all_vs if version.parse(v) > version.parse(cur_ver)]
        except InvalidVersion:
            logger.error(f"InvalidVersion: Cannot parse current version '{cur_ver}' for package {pkg}")
            newer = []
        latest = all_vs[-1] if all_vs else 'unknown'

        deps = info.get('info', {}).get('requires_dist') or []

        suggested = suggest_upgrade_version(all_vs, cur_ver)

        rows.append({
            'Package Name': pkg,
            'Current Version': cur_ver,
            'All Available Versions': ', '.join(all_vs),
            'Newer Versions': ', '.join(newer),
            'Latest Version': latest,
            'Suggested Upgrade': suggested,
            'Dependencies for Latest': '; '.join(deps),
            'Vulnerable?': 'Yes' if pkg.lower() in vuln_map else 'No',
            'Vulnerability Details': vuln_map.get(pkg.lower(), '')
        })

    # 2. write CSV
    fieldnames = list(rows[0].keys()) if rows else []
    with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"✅ CSV report saved to {OUTPUT_CSV}")

    # 3. write HTML via Jinja2
    env = Environment(loader=FileSystemLoader('.'))
    template = env.from_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Dependency Upgrade Report</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                margin: 20px;
                background-color: #f5f6fa;
            }
            h2 {
                text-align: center;
                color: #333;
            }
            table {
                border-collapse: collapse;
                width: 100%;
                background: white;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                border-radius: 8px;
                overflow: hidden;
            }
            th, td {
                border: 1px solid #ddd;
                padding: 8px 12px;
                text-align: left;
                vertical-align: top;
            }
            th {
                background-color: #4CAF50;
                color: white;
                position: sticky;
                top: 0;
                z-index: 2;
            }
            tr:nth-child(even) {background-color: #f9f9f9;}
            tr:hover {background-color: #f1f1f1;}
            .vulnerable {background-color: #ffe6e6;}
            .upgradable {background-color: #e6f7ff;}
            .nowrap {white-space: nowrap;}
            tfoot input, tfoot select {
                width: 100%;
                box-sizing: border-box;
            }
        </style>
        <!-- DataTables -->
        <script src="https://code.jquery.com/jquery-3.7.0.min.js"></script>
        <script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
        <link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css">
    </head>
    <body>
        <h2>Dependency Upgrade Report</h2>
        <table id="reportTable">
            <thead>
                <tr>
                    {% for h in headers %}
                    <th>{{ h }}</th>
                    {% endfor %}
                </tr>
            </thead>
            <tfoot>
                <tr>
                    {% for h in headers %}
                    <th>{{ h }}</th>
                    {% endfor %}
                </tr>
            </tfoot>
            <tbody>
            {% for row in rows %}
                <tr class="
                    {% if row['Vulnerable?'] == 'Yes' %}vulnerable{% endif %}
                    {% if row['Suggested Upgrade'] not in ['Up-to-date', '', 'unknown'] %} upgradable{% endif %}
                ">
                {% for h in headers %}
                    {% if h == 'Package Name' %}
                        <td class="nowrap"><a href="https://pypi.org/project/{{ row[h] }}/" target="_blank">{{ row[h] }}</a></td>
                    {% else %}
                        <td>{{ row[h]|e }}</td>
                    {% endif %}
                {% endfor %}
                </tr>
            {% endfor %}
            </tbody>
        </table>

        <script>
        $(document).ready(function() {
            // DataTable 
            var table = $('#reportTable').DataTable({
                pageLength: 25,
                order: [[0, 'asc']]
            });

            // select
            $('#reportTable tfoot th').each(function() {
                var title = $(this).text();
                if (title !== '') {
                    $(this).html('<select><option value="">All</option></select>');
                }
            });

            table.columns().every(function() {
                var column = this;
                var select = $('select', column.footer());

                column.data().unique().sort().each(function(d, j) {
                    d = $('<div>').html(d).text();
                    if (d.length > 30) d = d.substring(0, 30) + '...';
                    select.append('<option value="' + d + '">' + d + '</option>')
                });

                select.on('change', function() {
                    var val = $.fn.dataTable.util.escapeRegex($(this).val());
                    column
                        .search(val ? '^' + val + '$' : '', true, false)
                        .draw();
                });
            });
        });
        </script>
    </body>
    </html>
    """)


    html = template.render(headers=fieldnames, rows=rows)
    with open(OUTPUT_HTML, 'w', encoding='utf-8') as f:
        f.write(html)
    print(f"✅ HTML report saved to {OUTPUT_HTML}")

if __name__ == '__main__':
    main()
