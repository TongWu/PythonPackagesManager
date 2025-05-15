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
import argparse
import os
from datetime import datetime, timedelta

import asyncio
import aiohttp

# ---------------- Configuration ----------------
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

REQUIREMENTS_FILE = 'requirements_full_list.txt'
PIP_AUDIT_CMD = ['pip-audit', '--format', 'json']
PYPI_URL_TEMPLATE = 'https://pypi.org/pypi/{package}/json'

semaphore_number = 3
failed_versions = []
# ------------------------------------------------

def get_report_paths():
    today = datetime.today()
    monday = today - timedelta(days=today.weekday()) 
    folder_name = monday.strftime("%Y-%m-%d")
    timestamp = today.strftime("%Y-%m-%d_%H-%M-%S")
    output_dir = os.path.join("WeeklyReport", folder_name)
    os.makedirs(output_dir, exist_ok=True)

    return {
        "dir": output_dir,
        "csv": os.path.join(output_dir, f"WeeklyReport_{timestamp}.csv"),
        "html": os.path.join(output_dir, f"WeeklyReport_{timestamp}.html"),
        "json": os.path.join(output_dir, f"WeeklyReport_{timestamp}.json"),
        "failed": os.path.join(output_dir, f"FailedVersions_{timestamp}.txt")
    }


def get_report_output_folder(base="WeeklyReport"):
    today = datetime.today()
    monday = today - timedelta(days=today.weekday()) 
    folder_name = monday.strftime("%Y-%m-%d")
    path = os.path.join(base, folder_name)
    os.makedirs(path, exist_ok=True)
    return path


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

def check_osv_vulnerabilities(package, ver):
    """Query osv.dev for vulnerabilities of a specific package version"""
    try:
        payload = {
            "package": {
                "name": package,
                "ecosystem": "PyPI"
            },
            "version": ver
        }
        r = requests.post("https://api.osv.dev/v1/query", json=payload, timeout=5)
        if r.status_code == 200:
            data = r.json()
            vulns = data.get('vulns', [])
            if not vulns:
                return 'No', ''
            details = [f"{v['id']} - {v.get('summary', '')}" for v in vulns]
            return 'Yes', '; '.join(details)
    except Exception as e:
        logger.warning(f"OSV check failed for {package}=={ver}: {e}")
    return 'unknown', ''


async def fetch_osv(session, package, ver, sem, retry=3):
    """Async fetch vulnerability info for a specific version"""
    url = "https://api.osv.dev/v1/query"
    payload = {
        "package": {
            "name": package,
            "ecosystem": "PyPI"
        },
        "version": ver
    }
    for attempt in range(retry):
        try:
            async with sem:
                async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=30)) as r:
                    if r.status == 200:
                        data = await r.json()
                        vulns = data.get('vulns', [])
                        if not vulns:
                            return ver, 'No', ''
                        details = []
                        for v in vulns:
                            aliases = v.get('aliases', [])
                            vuln_id = next((a for a in aliases if a.startswith("CVE-")), v.get('id', ''))
                            summary = v.get('summary', '')
                            severity = 'UNKNOWN'
                            score = ''

                            if 'severity' in v and v['severity']:
                                s = v['severity'][0]
                                severity = s.get('type', 'UNKNOWN')
                                score = s.get('score', '')
                            elif 'cvss' in v.get('database_specific', {}):
                                cvss = v['database_specific']['cvss']
                                severity = cvss.get('severity', 'UNKNOWN')
                                score = str(cvss.get('score', ''))

                            # Parse affected version ranges
                            affected_versions = set()
                            for aff in v.get('affected', []):
                                version_ranges = []
                                for r in aff.get('ranges', []):
                                    if r.get('type') == 'ECOSYSTEM':
                                        for evt in r.get('events', []):
                                            if 'introduced' in evt:
                                                version_ranges.append(f">={evt['introduced']}")
                                            if 'fixed' in evt:
                                                version_ranges.append(f"<{evt['fixed']}")
                                if version_ranges:
                                    affected_versions.add(','.join(version_ranges))

                            affected_str = '; '.join(affected_versions) or 'unknown'

                            details.append(f"{vuln_id}, {severity}, {summary}, {score}, affects: {affected_str}")
                        
                        return ver, 'Yes', '\n'.join(details)
        except Exception as e:
            logger.warning(f"[async] OSV check failed for {package}=={ver}: {repr(e)}")
            failed_versions.append(f"{package}=={ver}")
    return ver, 'unknown', ''

async def check_multiple_versions(package, versions, smp_num):
    """Check multiple versions asynchronously for vulnerabilities"""
    results = {}
    sem = asyncio.Semaphore(smp_num)
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_osv(session, package, v, sem) for v in versions]
        for coro in asyncio.as_completed(tasks):
            ver, flag, details = await coro
            results[ver] = (flag, details)
    return results

def main():
    paths = get_report_paths()
    report_dir = get_report_output_folder()

    OUTPUT_CSV = paths["csv"]
    OUTPUT_HTML = paths["html"]
    OUTPUT_JSON = paths["json"]
    OUTPUT_FAILED = paths["failed"]

    parser = argparse.ArgumentParser(description="Dependency vulnerability scanner")
    parser.add_argument('--output', nargs='+', choices=['csv', 'html', 'json', 'all'], default=['all'],
                        help="Choose one or more output formats (e.g. --output csv html)")
    args = parser.parse_args()

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

        # default values if no upgrade
        upgrade_vuln_map = asyncio.run(check_multiple_versions(pkg, newer, semaphore_number))

        # aggregate
        upgrade_vuln = 'Yes' if any(v[0] == 'Yes' for v in upgrade_vuln_map.values()) else 'No'
        upgrade_vuln_details = '; '.join(
            f"{ver}: {details}" for ver, (flag, details) in upgrade_vuln_map.items() if flag == 'Yes'
        ) or 'None'

        rows.append({
            'Package Name': pkg,
            'Current Version': cur_ver,
            'All Available Versions': ', '.join(all_vs),
            'Newer Versions': ', '.join(newer),
            'Latest Version': latest,
            'Suggested Upgrade': suggested,
            'Dependencies for Latest': '; '.join(deps),
            'Vulnerable?': 'Yes' if pkg.lower() in vuln_map else 'No',
            'Vulnerability Details': vuln_map.get(pkg.lower(), ''),
            'Upgrade Version Vulnerable?': upgrade_vuln,
            'Upgrade Vulnerability Details': upgrade_vuln_details
        })

    # 3. write HTML via Jinja2
    env = Environment(loader=FileSystemLoader('templates'))
    template = env.get_template('weekly_report.html.j2')

    output_set = set(args.output)
    if 'all' in output_set:
        output_set = {'csv', 'html', 'json'}

    if 'csv' in output_set:
        with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8-sig') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        print(f"✅ CSV report saved to {OUTPUT_CSV}")

    if 'html' in output_set:
        env = Environment(loader=FileSystemLoader('.'))
        template = env.from_string("""...""")
        html = template.render(headers=fieldnames, rows=rows)
        with open(OUTPUT_HTML, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"✅ HTML report saved to {OUTPUT_HTML}")

    if 'json' in output_set:
        with open(OUTPUT_JSON, 'w', encoding='utf-8') as jf:
            json.dump(rows, jf, indent=2, ensure_ascii=False)
        print("✅ JSON report saved to dependency_report.json")


    if failed_versions:
        with open(OUTPUT_FAILED, 'w') as f:
            f.write('\n'.join(failed_versions))
        logger.warning(f"⚠️ {len(failed_versions)} package versions failed vulnerability check. Saved to failed_versions.txt")


if __name__ == '__main__':
    main()
