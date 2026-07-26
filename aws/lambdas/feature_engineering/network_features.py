"""
Network Feature Engineering

Generates network-based ML features from
validated security events.

Responsibilities
----------------
- Internal / External IP
- Private / Public IP
- Same Subnet
- Network Direction
- Port Categories
- Well Known Ports
- IPv4 / IPv6
- Loopback Detection

Author:
AI Threat Detection Dashboard
"""

from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass
from typing import Dict

from .config import INTERNAL_NETWORKS
from .constants import WELL_KNOWN_PORTS
# ---------------------------------------------------------
# Network Features
# ---------------------------------------------------------

@dataclass(slots=True)
class NetworkFeatures:

    src_internal: int

    dest_internal: int

    src_private: int

    dest_private: int

    src_loopback: int

    dest_loopback: int

    same_subnet: int

    network_direction: int

    ip_version: int

    src_port_category: int

    dest_port_category: int

    src_well_known: int

    dest_well_known: int

    privileged_src_port: int

    privileged_dest_port: int
    # ---------------------------------------------------------
# Generator
# ---------------------------------------------------------

class NetworkFeatureGenerator:

    """
    Generates network features from
    source/destination information.
    """

    def __init__(self):

        self.internal_networks = [

            ipaddress.ip_network(net)

            for net in INTERNAL_NETWORKS

        ]
        # -----------------------------------------------------
    # Internal Network
    # -----------------------------------------------------

    def _is_internal(
        self,
        ip: str,
    ) -> bool:

        ip_addr = ipaddress.ip_address(ip)

        return any(

            ip_addr in network

            for network in self.internal_networks

        )
        # -----------------------------------------------------
    # Private IP
    # -----------------------------------------------------

    @staticmethod
    def _is_private(
        ip: str,
    ) -> bool:

        return ipaddress.ip_address(

            ip

        ).is_private
        # -----------------------------------------------------
    # Loopback
    # -----------------------------------------------------

    @staticmethod
    def _is_loopback(
        ip: str,
    ) -> bool:

        return ipaddress.ip_address(

            ip

        ).is_loopback
        # -----------------------------------------------------
    # Same Subnet (/24 IPv4)
    # -----------------------------------------------------

    @staticmethod
    def _same_subnet(
        src: str,
        dest: str,
    ) -> bool:

        src_ip = ipaddress.ip_address(src)

        dest_ip = ipaddress.ip_address(dest)

        if src_ip.version != dest_ip.version:

            return False

        if src_ip.version == 4:

            src_net = ipaddress.ip_network(

                f"{src}/24",

                strict=False,

            )

            return dest_ip in src_net

        return False
        # -----------------------------------------------------
    # Port Category
    # -----------------------------------------------------

    @staticmethod
    def _port_category(
        port: int | None,
    ) -> int:

        if port is None:

            return 0

        if port in WELL_KNOWN_PORTS:

            return 1

        if 0 <= port <= 1023:

            return 2

        if 1024 <= port <= 49151:

            return 3

        if 49152 <= port <= 65535:

            return 4

        return 0

    # -----------------------------------------------------
    # Well Known Port
    # -----------------------------------------------------

    @staticmethod
    def _is_well_known(
        port: int | None,
    ) -> bool:

        if port is None:

            return False

        return port in WELL_KNOWN_PORTS

    # -----------------------------------------------------
    # Privileged Port
    # -----------------------------------------------------

    @staticmethod
    def _is_privileged(
        port: int | None,
    ) -> bool:

        if port is None:

            return False

        return 0 <= port <= 1023

    # -----------------------------------------------------
    # IP Version
    # -----------------------------------------------------

    @staticmethod
    def _ip_version(
        ip: str,
    ) -> int:

        return ipaddress.ip_address(

            ip

        ).version

    # -----------------------------------------------------
    # Network Direction
    # -----------------------------------------------------

    def _network_direction(
        self,
        src_internal: bool,
        dest_internal: bool,
    ) -> int:

        #
        # Encoding
        #
        # 1 = Internal
        # 2 = Outbound
        # 3 = Inbound
        # 4 = External
        #

        if src_internal and dest_internal:

            return 1

        if src_internal and not dest_internal:

            return 2

        if not src_internal and dest_internal:

            return 3

        return 4
        # -----------------------------------------------------
    # Generate
    # -----------------------------------------------------

    def generate(
        self,
        src_ip: str,
        dest_ip: str,
        src_port: int | None = None,
        dest_port: int | None = None,
    ) -> NetworkFeatures:

        src_internal = self._is_internal(

            src_ip

        )

        dest_internal = self._is_internal(

            dest_ip

        )

        return NetworkFeatures(

            src_internal=int(src_internal),

            dest_internal=int(dest_internal),

            src_private=int(

                self._is_private(src_ip)

            ),

            dest_private=int(

                self._is_private(dest_ip)

            ),

            src_loopback=int(

                self._is_loopback(src_ip)

            ),

            dest_loopback=int(

                self._is_loopback(dest_ip)

            ),

            same_subnet=int(

                self._same_subnet(

                    src_ip,

                    dest_ip,

                )

            ),

            network_direction=self._network_direction(

                src_internal,

                dest_internal,

            ),

            ip_version=self._ip_version(

                src_ip

            ),

            src_port_category=self._port_category(

                src_port

            ),

            dest_port_category=self._port_category(

                dest_port

            ),

            src_well_known=int(

                self._is_well_known(

                    src_port

                )

            ),

            dest_well_known=int(

                self._is_well_known(

                    dest_port

                )

            ),

            privileged_src_port=int(

                self._is_privileged(

                    src_port

                )

            ),

            privileged_dest_port=int(

                self._is_privileged(

                    dest_port

                )

            ),

        )

    # -----------------------------------------------------
    # Dictionary Output
    # -----------------------------------------------------

    def generate_dict(
        self,
        src_ip: str,
        dest_ip: str,
        src_port: int | None = None,
        dest_port: int | None = None,
    ) -> Dict:

        return asdict(

            self.generate(

                src_ip,

                dest_ip,

                src_port,

                dest_port,

            )

        )
        # -----------------------------------------------------
    # Batch Generation
    # -----------------------------------------------------

    def generate_batch(
        self,
        events,
    ):

        features = []

        for event in events:

            features.append(

                self.generate_dict(

                    event.src_ip,

                    event.dest_ip,

                    event.src_port,

                    event.dest_port,

                )

            )

        return features


# ---------------------------------------------------------
# Singleton
# ---------------------------------------------------------

_generator = NetworkFeatureGenerator()


def generate_network_features(
    src_ip: str,
    dest_ip: str,
    src_port: int | None = None,
    dest_port: int | None = None,
) -> Dict:

    return _generator.generate_dict(

        src_ip,

        dest_ip,

        src_port,

        dest_port,

    )


# ---------------------------------------------------------
# Local Testing
# ---------------------------------------------------------

if __name__ == "__main__":

    from pprint import pprint

    result = generate_network_features(

        src_ip="192.168.1.25",

        dest_ip="8.8.8.8",

        src_port=51234,

        dest_port=443,

    )

    pprint(result)