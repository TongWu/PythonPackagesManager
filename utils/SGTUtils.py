#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Custom logging formatter that ensures timestamps are in Asia/Singapore timezone.
Compatible with Python 3.9+ (using zoneinfo) and Python <3.9 (fallback to pytz).
"""

from logging import Formatter
from datetime import datetime

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

# Timezone support for UTC+8 (Singapore)
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