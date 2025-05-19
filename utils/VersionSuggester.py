#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Suggest upgrade versions for a Python package.
"""

import utils
from packaging import version
import requests
import argparse
import logging
from packaging.version import InvalidVersion
from logging import StreamHandler, Formatter
from datetime import datetime
from utils.SGTUtils import SGTFormatter
# Custom formatter (assumes SGTFormatter is defined elsewhere or should be implemented here)
try:
    from zoneinfo import ZoneInfo  # Python 3.9+
except ImportError:
    from pytz import timezone as ZoneInfo  # for Python <3.9

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = StreamHandler()
formatter = SGTFormatter(fmt='%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.propagate = False  # Avoid duplicate logs from root logger

PYPI_URL = "https://pypi.org/pypi/{package}/json"

def get_all_versions(pkg: str) -> list:
    """
    Fetch all release versions from PyPI.
    """
    r = requests.get(PYPI_URL.format(package=pkg), timeout=5)
    r.raise_for_status()
    data = r.json()
    return [v for v in data.get("releases", {})]

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

def suggest_safe_minor_upgrade(all_vs: list, cur_ver: str) -> str:
    """
    Suggest highest non-major-upgrade version without vulnerabilities.
    """
    cur = version.parse(cur_ver)
    candidates = []
    for v_str in all_vs:
        try:
            v = version.parse(v_str)
        except InvalidVersion:
            continue
        if v.major == cur.major and v > cur:
            flag, _ = check_vulnerability(pkg_name, v_str)
            if flag == 'No':
                candidates.append(v)
    if not candidates:
        return "No safe minor upgrade"
    return str(sorted(candidates)[-1])

def main():
    parser = argparse.ArgumentParser(description="Suggest upgrade versions")
    parser.add_argument("package", help="Package name on PyPI")
    parser.add_argument("current", help="Current installed version")
    parser.add_argument("--safe-minor", action="store_true",
                        help="Also suggest safe minor upgrade")
    args = parser.parse_args()

    global pkg_name
    pkg_name = args.package  # used in suggest_safe_minor_upgrade

    versions = get_all_versions(pkg_name)
    basic = suggest_upgrade_version(versions, args.current)
    print(f"Suggested upgrade: {basic}")

    if args.safe_minor:
        safe = suggest_safe_minor_upgrade(versions, args.current)
        print(f"Safe minor upgrade: {safe}")

if __name__ == "__main__":
    main()
