# -*- coding: utf-8 -*-
"""
General utilities: timezone, file paths, parsing and sorting helpers.
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

