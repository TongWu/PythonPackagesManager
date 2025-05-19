#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Check if a given Python package version has known vulnerabilities via OSV.
"""

import argparse
import asyncio
import aiohttp

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

async def check_vulnerability_async(pkg: str, version: str, concurrency: int = 3):
    """
    Async wrapper to check one version.
    """
    sem = asyncio.Semaphore(concurrency)
    async with aiohttp.ClientSession() as session:
        return await fetch_osv(session, pkg, version, sem)

def check_vulnerability(pkg: str, version: str, concurrency: int = 3):
    """
    Synchronous helper to call async check.
    """
    return asyncio.run(check_vulnerability_async(pkg, version, concurrency))

def main():
    parser = argparse.ArgumentParser(description="Check vulnerability for a Python package version")
    parser.add_argument("package", help="Package name on PyPI")
    parser.add_argument("version", help="Specific version to check")
    args = parser.parse_args()

    ver, flag, details = check_vulnerability(args.package, args.version)
    print(f"Version: {ver}")
    print(f"Vulnerable? {flag}")
    if details:
        print("Details:")
        print(details)

if __name__ == "__main__":
    main()
