#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Weekly vulnerability and upgrade report generator for Python packages.
Scans for known vulnerabilities using pip-audit and OSV, gathers PyPI metadata,
and outputs detailed weekly reports in CSV, HTML, and JSON formats.
"""

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
import time
from dotenv import load_dotenv
import shlex
import subprocess
import base64

# ---------------- Configuration ----------------
# Load environment variables from .env file
load_dotenv(dotenv_path=".env")

FULL_RELOAD_PACKAGES = os.getenv("FULL_RELOAD_PACKAGES", "False").lower() == "true"
BASE_PACKAGE_TXT = os.getenv("BASE_PACKAGE_TXT", "base_package_list.txt")
BASE_PACKAGE_CSV = os.getenv("BASE_PACKAGE_CSV", "BasePackageWithDependencies.csv")
CHECK_DEPENDENCY_SCRIPT = os.getenv("CHECK_DEPENDENCY_SCRIPT", "CheckDependency.py")
REQUIREMENTS_FILE = os.getenv("REQUIREMENTS_FILE", "requirements_full_list.txt")
PIP_AUDIT_CMD = shlex.split(os.getenv("PIP_AUDIT_CMD", "pip-audit --format json"))
PYPI_URL_TEMPLATE = os.getenv("PYPI_URL_TEMPLATE", "https://pypi.org/pypi/{package}/json")
SEMAPHORE_NUMBER = int(os.getenv("SEMAPHORE_NUMBER", 3))
failed_versions = []

# Timezone support for UTC+8 (Singapore)
from datetime import datetime
try:
    from zoneinfo import ZoneInfo  # Python 3.9+
except ImportError:
    from pytz import timezone as ZoneInfo  # fallback for Python <3.9
SG_TZ = ZoneInfo("Asia/Singapore")
def now_sg() -> datetime:
    """
    Get the current datetime in Singapore timezone (UTC+8).

    Returns:
        datetime: Current datetime in Asia/Singapore timezone.
    """
    return datetime.now(SG_TZ)

# ---------------- Logging Configuration with SGT timezone ----------------
from logging import Formatter, StreamHandler
try:
    from zoneinfo import ZoneInfo  # Python 3.9+
except ImportError:
    from pytz import timezone as ZoneInfo  # fallback for Python <3.9

SG_TZ = ZoneInfo("Asia/Singapore")

class SGTFormatter(Formatter):
    """
    Custom logging formatter that outputs timestamps in Asia/Singapore timezone.
    """
    def formatTime(self, record, datefmt=None):
        ct = datetime.fromtimestamp(record.created, SG_TZ)
        if datefmt:
            return ct.strftime(datefmt)
        return ct.isoformat()

# Configure logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = StreamHandler()
formatter = SGTFormatter(fmt='%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.propagate = False  # Avoid duplicate logs from root logger
# ---------------- Utility Functions ----------------
def decode_base64_env(var_name: str, default: str = "Unknown") -> str:
    """
    Decode a base64-encoded environment variable into a UTF-8 string.

    Args:
        var_name (str): The name of the environment variable to decode.
        default (str): Fallback value if decoding fails or variable not found.

    Returns:
        str: Decoded string value, or fallback default if not available or decoding fails.
    """
    val = os.getenv(var_name)
    if not val:
        return default

    try:
        return base64.b64decode(val).decode("utf-8")
    except Exception as e:
        logger.warning(f"Failed to decode base64 environment variable '{var_name}': {e}")
        return default

def get_report_paths() -> dict:
    """
    Generate all report file paths using current week and timestamp.

    Returns:
        dict: Dictionary with keys 'dir', 'csv', 'html', 'json', 'failed' pointing to file paths.
    """
    today = datetime.today()
    monday = today - timedelta(days=today.weekday()) 
    folder_name = monday.strftime("%Y-%m-%d")
    timestamp_sg = now_sg().strftime('%Y%m%d_%H%M%S')
    output_dir = os.path.join("WeeklyReport", folder_name)
    os.makedirs(output_dir, exist_ok=True)

    return {
        "dir": output_dir,
        "csv": os.path.join(output_dir, f"WeeklyReport_{timestamp_sg}.csv"),
        "html": os.path.join(output_dir, f"WeeklyReport_{timestamp_sg}.html"),
        "json": os.path.join(output_dir, f"WeeklyReport_{timestamp_sg}.json"),
        "failed": os.path.join(output_dir, f"FailedVersions_{timestamp_sg}.txt")
    }

def load_custodian_map(path: str = "custodian.csv") -> dict:
    """
    Load custodian information from a CSV file.

    Args:
        path (str): Path to the custodian.csv file.

    Returns:
        dict: Mapping of package_name.lower() -> (custodian, package_type)
    """
    mapping = {}
    try:
        with open(path, newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                pkg = row.get("package name", "").strip().lower()
                custodian = row.get("custodian", "").strip()
                pkg_type = row.get("package type", "").strip()
                if pkg:
                    mapping[pkg] = (custodian, pkg_type)
    except Exception as e:
        logger.error(f"Failed to load custodian map: {e}")
    return mapping

def custom_sort_key(row: dict, custom_order: dict) -> tuple:
    """
    Generate a composite sorting key for a package report row based on custodian and package type.

    Sorting priority:
        1. Custodian rank (based on external custom order mapping)
        2. Package type: 'Base Package' comes before 'Dependency Package'
        3. Package name in case-insensitive alphabetical order

    Args:
        row (dict): A dictionary representing a single row in the report.
        custom_order (dict): Mapping from custodian name to sort rank (e.g. {"Org1": 0, "Org2": 1}).

    Returns:
        tuple: Sorting key as (custodian_rank, package_type_rank, package_name_lower)
    """
    custodian = row.get("Custodian", "")
    custodian_rank = custom_order.get(custodian, len(custom_order))

    type_order = {"Base Package": 0, "Dependency Package": 1}
    pkg_type = row.get("Package Type", "")
    pkg_type_rank = type_order.get(pkg_type, 2)

    pkg_name = row.get("Package Name", "").lower()

    return (custodian_rank, pkg_type_rank, pkg_name)

def run_py(script_path: str) -> None:
    """
    Execute an external Python script and stream its output in real-time.

    The function runs a Python script as a subprocess, captures stdout and stderr,
    and logs each output line with timestamp using the configured logger.

    Args:
        script_path (str): Path to the Python script to execute.

    Returns:
        None
    """
    logger.info(f"Running {script_path}...")
    start_time = time.time()

    try:
        process = subprocess.Popen(
            ["python3", script_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1  # line-buffered
        )

        assert process.stdout is not None
        for line in process.stdout:
            logger.info(f"[{script_path}] {line.rstrip()}")

        process.wait()
        duration = time.time() - start_time

        if process.returncode == 0:
            logger.info(f"{script_path} executed successfully in {duration:.2f} seconds.")
        else:
            logger.error(f"{script_path} failed in {duration:.2f} seconds with return code {process.returncode}")

    except Exception as e:
        logger.exception(f"Exception occurred while running {script_path}: {e}")

def load_base_packages() -> set:
    """
    Load base packages from either a CSV or a TXT file based on global setting.

    Returns:
        set: Set of lowercase package names classified as base packages.
    """
    base_set = set()
    try:
        if FULL_RELOAD_PACKAGES:
            logger.warning(f"FULL RELOAD PYTHON PACKAGES, CALLING {CHECK_DEPENDENCY_SCRIPT}")
            # Regenerate Base Packages Dependencies before loading
            run_py(CHECK_DEPENDENCY_SCRIPT)

            with open(BASE_PACKAGE_CSV, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    base_pkg = row.get("Base Package", "").strip()
                    if base_pkg:
                        base_set.add(base_pkg.lower())
            logger.info(f"Loaded {len(base_set)} base packages from {BASE_PACKAGE_CSV}")
        else:
            with open(BASE_PACKAGE_TXT, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        base_set.add(line.lower())
            logger.info(f"Loaded {len(base_set)} base packages from {BASE_PACKAGE_TXT}")
    except Exception as e:
        logger.warning(f"Failed to load base package list: {e}")
    return base_set

def get_report_output_folder(base: str = "WeeklyReport") -> str:
    """
    Create and return the output folder path for the current week's report.

    This function computes the folder name based on the Monday of the current week,
    creates the directory if it does not exist, and returns the path.

    Args:
        base (str): Base directory name for report folders. Default is "WeeklyReport".

    Returns:
        str: Full path to the output directory for the current week.
    """
    today = datetime.today()
    monday = today - timedelta(days=today.weekday()) 
    folder_name = monday.strftime("%Y-%m-%d")
    path = os.path.join(base, folder_name)
    os.makedirs(path, exist_ok=True)
    return path

def parse_requirements(requirements_file: str) -> dict:
    """
    Parse a requirements.txt file into a dictionary.

    Supports basic parsing of version constraints like ==, >=, <=, ~=, !=.

    Args:
        requirements_file (str): Path to a pip requirements file.

    Returns:
        dict: Mapping of package names to their specified version strings.
    """
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

def get_pypi_info(package: str) -> dict | None:
    """
    Fetch metadata from the PyPI JSON API for a given package.

    Args:
        package (str): Name of the package.

    Returns:
        dict | None: JSON response from PyPI if successful, otherwise None.
    """
    url = PYPI_URL_TEMPLATE.format(package=package)
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        logger.warning(f"Fetch PyPI metadata for {package} failed: {e}")
    return None

def suggest_upgrade_version(all_versions: list, current_version: str) -> str:
    """
    Suggest the most appropriate upgrade version from available versions.

    The function prioritizes the latest version within the same major release,
    and if none found, returns the overall latest version.

    Args:
        all_versions (list): All available version strings.
        current_version (str): Current installed version string.

    Returns:
        str: Suggested version to upgrade to, 'Up-to-date' if none, or 'unknown' on error.
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

def extract_dependencies(info: dict) -> list:
    """
    Extract dependency information from PyPI metadata.

    Args:
        info (dict): JSON metadata returned from PyPI.

    Returns:
        list: List of dependency strings (usually from 'requires_dist').
    """
    return info.get('info', {}).get('requires_dist') or []

async def check_cv_uv(pkg: str, cur_ver: str, newer: list, smp_num: int):
    """
    Asynchronously check both current and upgrade version vulnerabilities.

    This function runs two vulnerability scans in parallel:
    - One for the current installed version of a package
    - One for all newer available versions (potential upgrades)

    It shares the same aiohttp session and semaphore to optimize HTTP usage.

    Args:
        pkg (str): Name of the package.
        cur_ver (str): Current installed version.
        newer (list): List of newer version strings to check.
        smp_num (int): Maximum concurrency allowed for async tasks.

    Returns:
        tuple:
            - current_result (tuple): (version, status, details) for current version
            - upgrade_results (dict): version -> (status, details) mapping for upgrade candidates
    """
    sem = asyncio.Semaphore(smp_num)
    async with aiohttp.ClientSession() as session:
        current_task = fetch_osv(session, pkg, cur_ver, sem)
        upgrade_task = check_multiple_versions(pkg, newer, smp_num, session=session, shared_sem=sem)
        return await asyncio.gather(current_task, upgrade_task)

async def check_multiple_versions(
    package: str,
    versions: list,
    smp_num: int,
    session: aiohttp.ClientSession = None,
    shared_sem: asyncio.Semaphore = None
) -> dict:
    """
    Perform asynchronous OSV vulnerability checks on multiple versions of a package.

    Args:
        package (str): Package name to check.
        versions (list): List of version strings to scan.
        smp_num (int): Maximum concurrency allowed for scanning.
        session (aiohttp.ClientSession, optional): Shared aiohttp session. Will create a new one if not provided.
        shared_sem (asyncio.Semaphore, optional): Shared semaphore to control concurrency. Will create a new one if not provided.

    Returns:
        dict: Mapping from version string to (vulnerable_flag, details) tuple.
              Example: {"1.2.3": ("Yes", "CVE-2022-xxxx ..."), "1.2.4": ("No", "")}
    """
    results = {}
    sem = shared_sem or asyncio.Semaphore(smp_num)
    owns_session = session is None

    if owns_session:
        session = aiohttp.ClientSession()

    try:
        tasks = [fetch_osv(session, package, v, sem) for v in versions]
        for coro in asyncio.as_completed(tasks):
            ver, flag, details = await coro
            results[ver] = (flag, details)
    finally:
        if owns_session:
            await session.close()

    return results

async def fetch_osv(session: aiohttp.ClientSession, package: str, ver: str,
                    sem: asyncio.Semaphore, retry: int = 3) -> tuple:
    """
    Asynchronously query osv.dev for vulnerabilities on a specific package version.

    Args:
        session (aiohttp.ClientSession): Reusable HTTP session.
        package (str): Name of the package.
        ver (str): Version string to check.
        sem (asyncio.Semaphore): Semaphore object to limit concurrency.
        retry (int): Number of retries upon failure (default: 3).

    Returns:
        tuple: (version (str), status (str), details (str))
            - status: 'Yes', 'No', or 'unknown'
            - details: Summary text or empty string
    """
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

        info = get_pypi_info(pkg)
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