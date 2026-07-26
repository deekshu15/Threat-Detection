from processors.windows_processor import WindowsProcessor
from processors.ids_processor import IDSProcessor
from processors.linux_processor import LinuxProcessor
from processors.firewall_processor import FirewallProcessor
from processors.cve_processor import CVEProcessor


class ProcessorFactory:
    """Factory for creating security log processors."""

    PROCESSORS = {
        "windows": WindowsProcessor,
        "ids": IDSProcessor,
        "linux": LinuxProcessor,
        "firewall": FirewallProcessor,
        "cve": CVEProcessor,
    }

    @staticmethod
    def create(dataset_type: str):
        processor = ProcessorFactory.PROCESSORS.get(dataset_type)

        if processor is None:
            raise ValueError(f"No processor available for '{dataset_type}'")

        return processor()