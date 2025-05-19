#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Weekly vulnerability and upgrade report generator for Python packages.
Scans for known vulnerabilities using pip-audit and OSV, gathers PyPI metadata,
and outputs detailed weekly reports in CSV, HTML, and JSON formats.
"""
import os
import csv
import json
import logging
import shlex
import argparse
import asyncio
from dotenv import load_dotenv
from datetime import datetime
from logging import StreamHandler, Formatter
from packaging import version
from packaging.version import InvalidVersion
from jinja2 import Environment, FileSystemLoader
from utils.ConfigUtils import(
    get_report_paths,
    get_report_output_folder,
    load_base_packages,
    parse_requirements
)
from utils.CustodianUtils import(
    load_custodian_map,
    decode_base64_env,
    custom_sort_key
)
from utils.PyPiUtils import (
    GetPyPiInfo
)
from utils.VersionSuggester import (
    suggest_upgrade_version
)
from utils.VulnChecker import (
    check_cv_uv
)
from utils.SGTUtils import (
    SGTFormatter,
    now_sg
)

# ---------------- Configuration ----------------
# Load environment variables from .env file
load_dotenv(dotenv_path=".env")

FULL_RELOAD_PACKAGES = os.getenv("FULL_RELOAD_PACKAGES", "False").lower() == "true"
BASE_PACKAGE_TXT = os.getenv("BASE_PACKAGE_TXT", "base_package_list.txt")
BASE_PACKAGE_CSV = os.getenv("BASE_PACKAGE_CSV", "BasePackageWithDependencies.csv")
CHECK_DEPENDENCY_SCRIPT = os.getenv("CHECK_DEPENDENCY_SCRIPT", "CheckDependency.py")
REQUIREMENTS_FILE = os.getenv("REQUIREMENTS_FILE", "requirements_full_list.txt")
PIP_AUDIT_CMD = shlex.split(os.getenv("PIP_AUDIT_CMD", "pip-audit --format json"))
SEMAPHORE_NUMBER = int(os.getenv("SEMAPHORE_NUMBER", 3))
failed_versions = []

# Configure logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = StreamHandler()
formatter = SGTFormatter(fmt='%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.propagate = False  # Avoid duplicate logs from root logger
# ---------------- Utility Functions ----------------
def main() -> None:
    """
    Main entry point for generate weekly report workflow.

    - Parses the requirements file.
    - Fetches metadata and known vulnerabilities.
    - Suggests upgrades and gathers dependency info.
    - Outputs reports in selected formats (CSV, HTML, JSON).

    Returns:
        None
    """
    paths = get_report_paths()
    report_dir = get_report_output_folder()

    OUTPUT_CSV = paths["csv"]
    OUTPUT_HTML = paths["html"]
    OUTPUT_JSON = paths["json"]
    OUTPUT_FAILED = paths["failed"]

    # Load base package list
    base_packages = load_base_packages()

    parser = argparse.ArgumentParser(description="Dependency vulnerability scanner")
    parser.add_argument('--output', nargs='+', choices=['csv', 'html', 'json', 'all'], default=['all'],
                        help="Choose one or more output formats (e.g. --output csv html)")
    args = parser.parse_args()

    pkgs = parse_requirements(REQUIREMENTS_FILE)

    rows = []

    # Load Custodian Mapping
    CUSTODIAN_MAP = {
    "1": decode_base64_env("CUSTODIAN_1"),
    "2": decode_base64_env("CUSTODIAN_2")
    }
    custodian_ordering = {v: i for i, v in enumerate(CUSTODIAN_MAP.values())}
    custodian_map = load_custodian_map()

    for idx, (pkg, cur_ver) in enumerate(pkgs.items(), 1):
        logger.info(f"[{idx}/{len(pkgs)}] Processing package: {pkg}, current version: {cur_ver}")

        info = GetPyPiInfo(pkg)
        if info:
            # Filter out invalid versions before sorting
            raw_versions = info.get('releases', {}).keys()
            valid_versions = []
            for v in raw_versions:
                try:
                    parsed_v = version.parse(v)
                    valid_versions.append(v)
                except InvalidVersion:
                    logger.warning(f"Package {pkg} has invalid version string skipped: {v}")

            all_vs = sorted(valid_versions, key=version.parse)

            cur_ver_deps = []
            release_info = info.get('releases', {}).get(cur_ver, [])
            if release_info:
                for entry in release_info:
                    if 'requires_dist' in entry:
                        cur_ver_deps.extend(entry['requires_dist'])
                        break
            if not cur_ver_deps:
                cur_ver_deps = info.get('info', {}).get('requires_dist') or []

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

        # run both current + upgrade checks in parallel
        (cv_ver, cv_status, cv_details), upgrade_vuln_map = asyncio.run(
            check_cv_uv(pkg, cur_ver, newer, SEMAPHORE_NUMBER)
        )

        # aggregate
        upgrade_vuln = 'Yes' if any(v[0] == 'Yes' for v in upgrade_vuln_map.values()) else 'No'
        upgrade_vuln_details = '; '.join(
            f"{ver}: {details}" for ver, (flag, details) in upgrade_vuln_map.items() if flag == 'Yes'
        ) or 'None'

        # Get custodian
        custodian, _ = custodian_map.get(pkg.lower(), ("Unknown", "Dependency Package"))

        rows.append({
            'Package Name': pkg,
            'Package Type': 'Base Package' if pkg.lower() in base_packages else 'Dependency Package',
            'Custodian': custodian,
            'Current Version': cur_ver,
            'Dependencies for Current': '; '.join(cur_ver_deps),
            # 'All Available Versions': ', '.join(all_vs),
            'Newer Versions': ', '.join(newer),
            'Dependencies for Latest': '; '.join(deps),
            'Latest Version': latest,
            'Suggested Upgrade': suggested,
            'Current Version Vulnerable?': cv_status,
            'Current Version Vulnerability Details': cv_details,
            'Upgrade Version Vulnerable?': upgrade_vuln,
            'Upgrade Vulnerability Details': upgrade_vuln_details
        })

    # Sort output with specific order
    rows.sort(key=lambda row: custom_sort_key(row, custodian_ordering))

    # write output
    fieldnames = list(rows[0].keys()) if rows else []
    output_set = set(args.output)
    if 'all' in output_set:
        output_set = {'csv', 'html', 'json'}

    if 'csv' in output_set:
        try:
            with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8-sig') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)
            print(f"✅ CSV report saved to {OUTPUT_CSV}")
        except Exception as e:
            print(f"❌ Failed to write CSV: {e}")

    if 'html' in output_set:
        try:
            env = Environment(loader=FileSystemLoader('templates'))
            template = env.get_template('weekly_report.html.j2')
            html = template.render(
                headers=fieldnames,
                rows=rows,
                generated_at=now_sg().strftime("%Y-%m-%d %H:%M:%S %Z")
            )

            with open(OUTPUT_HTML, 'w', encoding='utf-8') as f:
                f.write(html)
            print(f"✅ HTML report saved to {OUTPUT_HTML}")
        except Exception as e:
            print(f"❌ Failed to write HTML: {e}")

    if 'json' in output_set:
        try:
            with open(OUTPUT_JSON, 'w', encoding='utf-8') as jf:
                json.dump(rows, jf, indent=2, ensure_ascii=False)
            print(f"✅ JSON report saved to {OUTPUT_JSON}")
        except Exception as e:
            print(f"❌ Failed to write JSON: {e}")

    if failed_versions:
        try:
            with open(OUTPUT_FAILED, 'w') as f:
                f.write('\n'.join(failed_versions))
            logger.warning(f"⚠️ {len(failed_versions)} package versions failed vulnerability check. Saved to {OUTPUT_FAILED}.txt")
        except Exception as e:
            print(f"❌ Failed to write failed packages list: {e}")
    
    # Summary logging
    total = len(rows)
    base_count = sum(1 for r in rows if r['Package Type'] == 'Base Package')
    dep_count = total - base_count

    base_vuln = sum(1 for r in rows if r['Package Type'] == 'Base Package' and r['Current Version Vulnerable?'] == 'Yes')
    dep_vuln = sum(1 for r in rows if r['Package Type'] == 'Dependency Package' and r['Current Version Vulnerable?'] == 'Yes')

    logger.info("📦 Weekly Report Summary")
    logger.info(f"🔍 Total packages scanned: {total} (Base: {base_count}, Dependency: {dep_count})")
    logger.info(f"🚨 Vulnerabilities found in current versions:")
    logger.info(f"   • Base packages: {base_vuln} / {base_count}")
    logger.info(f"   • Dependency packages: {dep_vuln} / {dep_count}")

if __name__ == '__main__':
    main()