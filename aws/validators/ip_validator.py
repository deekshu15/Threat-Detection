"""
IP Validator

Provides reusable IPv4/IPv6 validation and classification utilities.

Responsibilities
----------------
• Validate IPv4 addresses
• Validate IPv6 addresses
• Validate CIDR networks
• Normalize IP addresses
• Detect private/public IPs
• Detect loopback, multicast, reserved addresses
• Determine IP version

Author: AI-Assisted Threat Detection Dashboard
Python: 3.11+
"""

from __future__ import annotations

import ipaddress
from typing import Any

from ..lambdas.threat_enrichment.exceptions import (
    InvalidIPAddressError,
    ValidationError,
)
from .base_validator import BaseValidator


class IPValidator(BaseValidator):
    """
    Reusable IP validation utilities.
    """

    validator_name = "IPValidator"

    def validate(self, raw_event: dict[str, Any]):
        """
        Base interface implementation.

        IPValidator is intended to be used through its helper
        methods rather than validating an entire ThreatEvent.
        """
        raise NotImplementedError(
            "Use validate_ip() or validate_network()."
        )

    # ===============================================================
    # Basic Validation
    # ===============================================================

    def validate_ip(
        self,
        ip: str,
    ) -> str:
        """
        Validate IPv4/IPv6 address.

        Returns normalized representation.
        """

        try:
            return str(ipaddress.ip_address(ip))

        except Exception as exc:
            raise InvalidIPAddressError(ip) from exc

    def validate_network(
        self,
        network: str,
    ) -> str:
        """
        Validate CIDR network.
        """

        try:
            return str(
                ipaddress.ip_network(
                    network,
                    strict=False,
                )
            )

        except Exception as exc:
            raise ValidationError(
                f"Invalid CIDR network: {network}"
            ) from exc

    # ===============================================================
    # IP Version
    # ===============================================================

    def version(
        self,
        ip: str,
    ) -> int:

        return ipaddress.ip_address(ip).version

    def is_ipv4(
        self,
        ip: str,
    ) -> bool:

        return self.version(ip) == 4

    def is_ipv6(
        self,
        ip: str,
    ) -> bool:

        return self.version(ip) == 6

    # ===============================================================
    # Address Types
    # ===============================================================

    def is_private(
        self,
        ip: str,
    ) -> bool:

        return ipaddress.ip_address(ip).is_private

    def is_public(
        self,
        ip: str,
    ) -> bool:

        address = ipaddress.ip_address(ip)

        return (
            not address.is_private
            and not address.is_loopback
            and not address.is_multicast
            and not address.is_reserved
            and not address.is_unspecified
        )

    def is_loopback(
        self,
        ip: str,
    ) -> bool:

        return ipaddress.ip_address(ip).is_loopback

    def is_multicast(
        self,
        ip: str,
    ) -> bool:

        return ipaddress.ip_address(ip).is_multicast

    def is_reserved(
        self,
        ip: str,
    ) -> bool:

        return ipaddress.ip_address(ip).is_reserved

    def is_unspecified(
        self,
        ip: str,
    ) -> bool:

        return ipaddress.ip_address(ip).is_unspecified

    def is_link_local(
        self,
        ip: str,
    ) -> bool:

        return ipaddress.ip_address(ip).is_link_local

    # ===============================================================
    # Classification
    # ===============================================================

    def classify(
        self,
        ip: str,
    ) -> dict[str, Any]:
        """
        Return metadata about an IP address.
        """

        address = ipaddress.ip_address(ip)

        return {
            "ip": str(address),
            "version": address.version,
            "private": address.is_private,
            "public": self.is_public(ip),
            "loopback": address.is_loopback,
            "multicast": address.is_multicast,
            "reserved": address.is_reserved,
            "link_local": address.is_link_local,
            "unspecified": address.is_unspecified,
            "compressed": address.compressed,
            "exploded": address.exploded,
        }

    # ===============================================================
    # Comparison
    # ===============================================================

    def same_network(
        self,
        ip1: str,
        ip2: str,
        prefix: int,
    ) -> bool:
        """
        Determine whether two IPs belong to the same network.
        """

        network = ipaddress.ip_network(
            f"{ip1}/{prefix}",
            strict=False,
        )

        return ipaddress.ip_address(ip2) in network

    # ===============================================================
    # Utility
    # ===============================================================

    def normalize(
        self,
        ip: str,
    ) -> str:
        """
        Normalize an IP address.
        """

        return str(ipaddress.ip_address(ip))

    def reverse_pointer(
        self,
        ip: str,
    ) -> str:
        """
        Return reverse DNS pointer.
        """

        return ipaddress.ip_address(ip).reverse_pointer