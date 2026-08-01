"""
Network Validator

Validates network-related fields and constructs a NetworkModel.

Responsibilities
----------------
• Validate IPv4/IPv6 addresses
• Validate ports
• Validate protocols
• Validate MAC addresses
• Normalize network data
• Build NetworkModel

Author: AI-Assisted Threat Detection Dashboard
Python: 3.11+
"""

from __future__ import annotations

import re
from typing import Any

from ..lambdas.threat_enrichment.constants import COMMON_PROTOCOLS
from ..lambdas.threat_enrichment.exceptions import (
    InvalidIPAddressError,
    InvalidPortError,
    ValidationError,
)
from ..models.network import (
    NetworkModel,
    Protocol,
)
from .base_validator import BaseValidator
from .ip_validator import IPValidator


class NetworkValidator(BaseValidator):
    """
    Network validation utilities.
    """

    validator_name = "NetworkValidator"

    MAC_REGEX = re.compile(
        r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
    )

    def __init__(self) -> None:
        super().__init__()
        self.ip_validator = IPValidator()

    def validate(self, raw_event: dict[str, Any]) -> NetworkModel:
        """
        Validate a raw network payload.
        """

        return self.build_network(raw_event)

    # ============================================================
    # Network Builder
    # ============================================================

    def build_network(
        self,
        data: dict[str, Any],
    ) -> NetworkModel:

        source_ip = self.validate_ip(
            data.get("source_ip")
        )

        destination_ip = self.validate_ip(
            data.get("destination_ip")
        )

        return NetworkModel(
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=self.validate_port(
                data.get("source_port", 0)
            ),
            destination_port=self.validate_port(
                data.get("destination_port", 0)
            ),
            protocol=self.validate_protocol(
                data.get("protocol", "TCP")
            ),
            bytes_in=int(data.get("bytes_in", 0)),
            bytes_out=int(data.get("bytes_out", 0)),
            packets=int(data.get("packets", 0)),
            payload_size=int(
                data.get("payload_size", 0)
            ),
            ttl=data.get("ttl"),
            tcp_flags=data.get("tcp_flags"),
            source_mac=self.validate_mac(
                data.get("source_mac")
            ),
            destination_mac=self.validate_mac(
                data.get("destination_mac")
            ),
            vlan=data.get("vlan"),
        )

    # ============================================================
    # IP Validation
    # ============================================================

    def validate_ip(
        self,
        ip: str | None,
    ) -> str | None:

        if ip is None:
            return None

        try:
            return self.ip_validator.validate_ip(ip)

        except Exception as exc:
            raise InvalidIPAddressError(ip) from exc

    # ============================================================
    # Port Validation
    # ============================================================

    @staticmethod
    def validate_port(
        port: Any,
    ) -> int:

        try:
            port = int(port)

        except Exception as exc:
            raise InvalidPortError(str(port)) from exc

        if not 0 <= port <= 65535:
            raise InvalidPortError(str(port))

        return port

    # ============================================================
    # Protocol Validation
    # ============================================================

    @staticmethod
    def validate_protocol(
        protocol: str,
    ) -> Protocol:

        if protocol is None:
            return Protocol.TCP

        protocol = protocol.upper()

        try:
            return Protocol(protocol)

        except ValueError:
            supported = {
                p.upper()
                for p in COMMON_PROTOCOLS
            }

            if protocol not in supported:
                raise ValidationError(
                    f"Unsupported protocol: {protocol}"
                )

            return Protocol(protocol)

    # ============================================================
    # MAC Validation
    # ============================================================

    def validate_mac(
        self,
        mac: str | None,
    ) -> str | None:

        if mac is None:
            return None

        mac = mac.strip()

        if not self.MAC_REGEX.match(mac):
            raise ValidationError(
                f"Invalid MAC address: {mac}"
            )

        return mac.upper()

    # ============================================================
    # Network Statistics
    # ============================================================

    @staticmethod
    def validate_counter(
        value: Any,
        field: str,
    ) -> int:

        try:
            value = int(value)

        except Exception as exc:
            raise ValidationError(
                f"Invalid {field}"
            ) from exc

        if value < 0:
            raise ValidationError(
                f"{field} cannot be negative."
            )

        return value

    # ============================================================
    # Utility Methods
    # ============================================================

    @staticmethod
    def is_ephemeral_port(
        port: int,
    ) -> bool:
        """
        RFC 6335 dynamic/private port range.
        """
        return 49152 <= port <= 65535

    @staticmethod
    def is_well_known_port(
        port: int,
    ) -> bool:
        """
        Well-known ports (0–1023).
        """
        return 0 <= port <= 1023

    @staticmethod
    def is_registered_port(
        port: int,
    ) -> bool:
        """
        Registered ports (1024–49151).
        """
        return 1024 <= port <= 49151