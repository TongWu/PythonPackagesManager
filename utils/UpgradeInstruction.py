#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generate upgrade instructions for a base package to a specific version,
including compatible and secure dependency versions.
"""
import asyncio
import aiohttp
import logging
from logging import StreamHandler, Formatter
from packaging.requirements import Requirement
from utils.PyPiUtils import GetPyPiInfo
from utils.VersionSuggester import suggest_safe_minor_upgrade
from utils.VulnChecker import fetch_osv
from packaging.version import Version, InvalidVersion
from packaging.specifiers import SpecifierSet
from utils.SGTUtils import SGTFormatter
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

def _extract_min_version(req: Requirement) -> str | None:
    """
    Return the minimal version that satisfies the requirement specifier.

    Rules
    -----
    1. If the requirement is pinned exactly (== or ===), return that version.
    2. Otherwise, pick the lowest version that appears in any >=, > or ~= bound.
    3. If no lower-bound specifier exists (e.g. just 'requests'), return None.

    Parameters
    ----------
    req : packaging.requirements.Requirement
        Parsed requirement object (already `Requirement(dep)` in your code).

    Returns
    -------
    str | None
        Minimal version as a string (e.g. "1.19.0") or None if not applicable.
    """
    if not req.specifier:
        return None

    min_version: str | None = None

    for spec in req.specifier:
        op, ver = spec.operator, spec.version
        try:
            ver_obj = Version(ver)
        except InvalidVersion:
            # Skip weird / local versions that Version() cannot parse
            continue

        # Case 1 – exact pin wins immediately
        if op in ("==", "==="):
            return ver

        # Case 2 – lower-bound candidates
        if op in (">=", ">", "~="):
            if min_version is None or ver_obj < Version(min_version):
                min_version = ver

    return min_version

async def get_safe_dependency_versions(dependencies: list[str]) -> dict:
    """
    For a list of dependency requirement strings, find the highest safe (non-vulnerable) version.
    """
    esults = {}
    async with aiohttp.ClientSession() as session:
        sem = asyncio.Semaphore(5)
        fetch_tasks, req_objs = [], []

        for dep in dependencies:
            try:
                req = Requirement(dep)
                req_objs.append(req)
                # 抓取全部版本列表
                fetch_tasks.append(fetch_osv(session, req.name, None, sem))
            except Exception as e:
                logger.warning(f"Failed to parse dependency: {dep}: {e}")

        fetched_versions = await asyncio.gather(*fetch_tasks, return_exceptions=True)

        # -------- 这里改动：await 协程 --------
        coroutines = []
        for req, all_versions in zip(req_objs, fetched_versions):
            min_ver = _extract_min_version(req)   # 你已有的那段逻辑，独立成私有函数更清爽
            if min_ver:
                coroutines.append(
                    suggest_safe_minor_upgrade(
                        pkg=req.name,
                        current_version=min_ver,
                        all_versions=all_versions,
                    )
                )
            else:
                coroutines.append(asyncio.sleep(0, result=None))  # 占位

        safe_versions = await asyncio.gather(*coroutines, return_exceptions=True)
        # -------------------------------------

        for req, safe in zip(req_objs, safe_versions):
            # 把异常或 Up-to-date 情况都处理掉，保证返回纯字符串或 None
            if isinstance(safe, Exception):
                logger.warning(f"Failed to get safe version for {req.name}: {safe}")
                continue
            results[req.name] = None if safe in (None, "Up-to-date") else safe
    return results

def generate_upgrade_instruction(base_package: str, target_version: str) -> dict:
    """
    Generate a detailed upgrade instruction including secure dependencies.
    """
    pypi = GetPyPiInfo(base_package)
    if not pypi:
        raise ValueError(f"Failed to fetch PyPI metadata for {base_package}")

    releases = pypi.get("releases", {})
    if target_version not in releases:
        raise ValueError(f"Target version {target_version} not found for {base_package}")

    requires_dist = pypi.get("info", {}).get("requires_dist") or []
    # logger.info(f"{base_package}=={target_version} requires: {requires_dist}")

    # Use asyncio.run to avoid 'event loop already running' issues
    safe_versions = asyncio.run(get_safe_dependency_versions(requires_dist))

    instruction = {
        "base_package": f"{base_package}=={target_version}",
        "dependencies": [f"{k}=={v}" for k, v in safe_versions.items() if v]
    }
    return instruction

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Generate secure upgrade instructions")
    parser.add_argument("package", help="Base package name")
    parser.add_argument("version", help="Target version")
    args = parser.parse_args()

    result = generate_upgrade_instruction(args.package, args.version)
    print("Upgrade Instruction:")
    print(result)