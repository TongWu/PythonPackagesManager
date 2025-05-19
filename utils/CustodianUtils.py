import utils
import os
import csv
import base64
import logging
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