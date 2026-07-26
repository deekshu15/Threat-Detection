import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from processors.factory import ProcessorFactory
from processors.windows_processor import WindowsProcessor
from processors.ids_processor import IDSProcessor
from processors.linux_processor import LinuxProcessor
from processors.firewall_processor import FirewallProcessor


# ---------- correct processor returned per dataset type ----------

@pytest.mark.parametrize(
    "dataset_type, expected_class",
    [
        ("windows", WindowsProcessor),
        ("ids", IDSProcessor),
        ("linux", LinuxProcessor),
        ("firewall", FirewallProcessor),
    ],
)
def test_factory_creates_correct_processor(dataset_type, expected_class):
    """Each known dataset type should return an instance of its matching processor class."""
    processor = ProcessorFactory.create(dataset_type)
    assert isinstance(processor, expected_class)


# ---------- unknown dataset type ----------

def test_factory_raises_for_unknown_dataset_type():
    """An unrecognized dataset type should raise ValueError, not return None or crash unexpectedly."""
    with pytest.raises(ValueError):
        ProcessorFactory.create("not_a_real_dataset_type")


def test_factory_error_message_mentions_the_bad_dataset_type():
    """The error message should be genuinely useful - it should name the type that failed."""
    with pytest.raises(ValueError, match="not_a_real_dataset_type"):
        ProcessorFactory.create("not_a_real_dataset_type")


# ---------- each call returns a fresh instance ----------

def test_factory_returns_a_new_instance_each_call():
    """Calling create() twice should return two separate objects, not the same shared instance."""
    processor1 = ProcessorFactory.create("windows")
    processor2 = ProcessorFactory.create("windows")
    assert processor1 is not processor2