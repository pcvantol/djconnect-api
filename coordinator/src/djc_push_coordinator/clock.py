"""Local Linux continuous clock only; deliberately supplies no qualified UTC."""
import sys
import time
from pathlib import Path


class ClockUnavailable(Exception):
    pass


class LinuxBootClock:
    def __init__(self):
        if sys.platform != "linux" or not hasattr(time, "CLOCK_BOOTTIME"):
            raise ClockUnavailable("Linux CLOCK_BOOTTIME unavailable")
        self.domain = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        if not self.domain:
            raise ClockUnavailable("boot domain unavailable")

    def continuous_ns(self):
        if Path("/proc/sys/kernel/random/boot_id").read_text().strip() != self.domain:
            raise ClockUnavailable("boot domain changed")
        return time.clock_gettime_ns(time.CLOCK_BOOTTIME)

    def utc_upper_ms(self):
        raise ClockUnavailable("no qualified UTC source/error/rate/age provider")
