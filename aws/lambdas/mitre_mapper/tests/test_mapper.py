import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from mitre_mapper import MITREMapper

mapper = MITREMapper()

print("=" * 70)
print("Testing MITRE Mapper")
print("=" * 70)

# ------------------------------------------------------
# Windows Event
# ------------------------------------------------------

windows_event = {
    "source": "windows",
    "event_type": 4625
}

print("\nWindows Event")
print(mapper.map_event(windows_event))

# ------------------------------------------------------
# IDS Event
# ------------------------------------------------------

ids_event = {
    "source": "ids",
    "event_type": "DDoS"
}

print("\nIDS Event")
print(mapper.map_event(ids_event))

# ------------------------------------------------------
# CVE Event
# ------------------------------------------------------

cve_event = {
    "source": "cve",
    "cwe": "CWE-22"
}

print("\nCVE Event")
print(mapper.map_event(cve_event))