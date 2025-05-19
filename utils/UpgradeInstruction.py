#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Generate upgrade instruction for a base package to a target version,
resolving its dependencies to safe versions without known vulnerabilities.
"""

import argparse
import requests
from packaging.requirements import Requirement
from packaging.version import parse, InvalidVersion
from vuln_checker import check_vulnerability

PYPI_URL = "https://pypi.org/pypi/{package}/{version}/json"
SEM = 3

def get_dependencies(pkg: str, ver: str) -> list:
    """
    Fetch the requires_dist list for a specific version.
    """
    r = requests.get(PYPI_URL.format(package=pkg, version=ver), timeout=5)
    r.raise_for_status()
    info = r.json().get("info", {})
    return info.get("requires_dist") or []

def select_safe_version(requirement: Requirement) -> str:
    """
    Given a Requirement object, pick the highest allowed version without vulnerabilities.
    """
    name = requirement.name
    # fetch all releases
    resp = requests.get(f"https://pypi.org/pypi/{name}/json", timeout=5)
    resp.raise_for_status()
    releases = resp.json().get("releases", {})
    allowed = []
    for v_str in releases:
        try:
            v = parse(v_str)
        except InvalidVersion:
            continue
        # check against specifier set
        if v in requirement.specifier:
            flag, _ = check_vulnerability(name, v_str, SEM)
            if flag == 'No':
                allowed.append(v)
    if not allowed:
        return None
    return str(sorted(allowed)[-1])

def main():
    parser = argparse.ArgumentParser(description="Generate pip install instruction for upgrade")
    parser.add_argument("package", help="Base package name")
    parser.add_argument("target_version", help="Target version to upgrade to")
    args = parser.parse_args()

    deps = get_dependencies(args.package, args.target_version)
    safe_deps = {}
    for req_str in deps:
        req = Requirement(req_str)
        safe_v = select_safe_version(req)
        safe_deps[req.name] = safe_v

    # build pip install command
    parts = [f"{args.package}=={args.target_version}"]
    for name, ver in safe_deps.items():
        if ver:
            parts.append(f"{name}=={ver}")

    cmd = "pip install " + " ".join(parts)
    print("Upgrade instruction:")
    print(cmd)

if __name__ == "__main__":
    main()
