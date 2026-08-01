"""
Enterprise Network Utilities

Features
--------
• Port Validation
• Protocol Validation
• URL Parsing
• DNS Resolution
• IP Detection
• Socket Helpers
"""

from __future__ import annotations

import socket

from urllib.parse import urlparse

from typing import Optional

from .ip_utils import is_valid_ip

import re

from dataclasses import dataclass

from .ip_utils import contains
from .ip_utils import parse_network


###########################################################################
# Ports
###########################################################################

MIN_PORT = 1
MAX_PORT = 65535


def is_valid_port(
    port: int,
) -> bool:

    return MIN_PORT <= port <= MAX_PORT


def is_system_port(
    port: int,
) -> bool:

    return 1 <= port <= 1023


def is_registered_port(
    port: int,
) -> bool:

    return 1024 <= port <= 49151


def is_dynamic_port(
    port: int,
) -> bool:

    return 49152 <= port <= 65535

###########################################################################
# Protocols
###########################################################################

_PROTOCOLS = {

    "tcp",

    "udp",

    "icmp",

    "icmpv6",

    "http",

    "https",

    "ftp",

    "ftps",

    "ssh",

    "telnet",

    "smtp",

    "pop3",

    "imap",

    "dns",

    "ntp",

    "snmp",

    "ldap",

    "rdp",

}


def normalize_protocol(
    protocol: str,
) -> str:

    return protocol.lower().strip()


def is_valid_protocol(
    protocol: str,
) -> bool:

    return normalize_protocol(
        protocol
    ) in _PROTOCOLS
    
    ###########################################################################
# URL
###########################################################################

def parse_url(
    url: str,
):

    return urlparse(url)


def hostname(
    url: str,
):

    return parse_url(
        url
    ).hostname


def scheme(
    url: str,
):

    return parse_url(
        url
    ).scheme


def url_port(
    url: str,
):

    return parse_url(
        url
    ).port


def path(
    url: str,
):

    return parse_url(
        url
    ).path
    
    ###########################################################################
# URL Validation
###########################################################################

def is_valid_url(
    url: str,
) -> bool:

    try:

        parsed = parse_url(url)

        return bool(

            parsed.scheme

            and

            parsed.netloc

        )

    except Exception:

        return False
    
    ###########################################################################
# DNS
###########################################################################

def resolve(
    host: str,
) -> Optional[str]:

    try:

        return socket.gethostbyname(
            host
        )

    except Exception:

        return None


def reverse_lookup(
    ip: str,
):

    try:

        return socket.gethostbyaddr(
            ip
        )[0]

    except Exception:

        return None
    
    ###########################################################################
# Host
###########################################################################

def is_hostname(
    value: str,
) -> bool:

    return (

        not is_valid_ip(value)

        and

        "." in value

    )


def is_ip_address(
    value: str,
) -> bool:

    return is_valid_ip(
        value
    )
    
    ###########################################################################
# Socket
###########################################################################

def service_name(
    port: int,
    protocol: str = "tcp",
):

    try:

        return socket.getservbyport(

            port,

            protocol,

        )

    except Exception:

        return None


def service_port(
    service: str,
    protocol: str = "tcp",
):

    try:

        return socket.getservbyname(

            service,

            protocol,

        )

    except Exception:

        return None
    
    ###########################################################################
# MAC Address
###########################################################################

_MAC_REGEX = re.compile(
    r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
)


def is_valid_mac(
    mac: str,
) -> bool:

    return bool(
        _MAC_REGEX.match(mac)
    )


def normalize_mac(
    mac: str,
) -> str:

    return (

        mac.upper()

        .replace("-", ":")

    )
    
    ###########################################################################
# Endpoint
###########################################################################

@dataclass(slots=True)
class Endpoint:

    host: str

    port: int

    protocol: str = "tcp"

    def __str__(self):

        return f"{self.protocol}://{self.host}:{self.port}"


def endpoint(
    host: str,
    port: int,
    protocol: str = "tcp",
) -> Endpoint:

    return Endpoint(

        host=host,

        port=port,

        protocol=normalize_protocol(protocol),

    )
    
    ###########################################################################
# Connectivity
###########################################################################

def is_port_open(
    host: str,
    port: int,
    timeout: float = 2.0,
) -> bool:

    try:

        with socket.create_connection(

            (host, port),

            timeout=timeout,

        ):

            return True

    except Exception:

        return False
    
    ###########################################################################
# Local Network
###########################################################################

def local_hostname():

    return socket.gethostname()


def local_ip():

    try:

        return socket.gethostbyname(

            socket.gethostname()

        )

    except Exception:

        return None
    
    ###########################################################################
# CIDR
###########################################################################

def in_network(
    ip: str,
    cidr: str,
) -> bool:

    return contains(

        cidr,

        ip,

    )


def network_size(
    cidr: str,
):

    return parse_network(

        cidr

    ).num_addresses
    
    ###########################################################################
# Batch DNS
###########################################################################

def resolve_many(
    hosts: list[str],
):

    return {

        host: resolve(host)

        for host in hosts

    }


def reverse_many(
    addresses: list[str],
):

    return {

        ip: reverse_lookup(ip)

        for ip in addresses

    }
    
    ###########################################################################
# Connectivity
###########################################################################

def scan_ports(
    host: str,
    ports: list[int],
    timeout: float = 1.0,
):

    return {

        port: is_port_open(

            host,

            port,

            timeout,

        )

        for port in ports

    }
    
    ###########################################################################
# Summary
###########################################################################

def endpoint_summary(
    host: str,
):

    ip = resolve(host)

    return {

        "hostname": host,

        "ip": ip,

        "reverse_dns": (

            reverse_lookup(ip)

            if ip

            else None

        ),

    }


def network_summary(
    cidr: str,
):

    network = parse_network(cidr)

    return {

        "network": str(network.network_address),

        "broadcast": (

            str(network.broadcast_address)

            if network.version == 4

            else None

        ),

        "prefix": network.prefixlen,

        "hosts": network.num_addresses,

    }
    
    ###########################################################################
# Common Ports
###########################################################################

_COMMON_PORTS = {

    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    135: "RPC",
    137: "NETBIOS",
    138: "NETBIOS",
    139: "SMB",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "SYSLOG",
    587: "SMTP",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "ORACLE",
    2049: "NFS",
    3306: "MYSQL",
    3389: "RDP",
    5432: "POSTGRESQL",
    6379: "REDIS",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",

}


def common_service(
    port: int,
):

    return _COMMON_PORTS.get(
        port,
        "UNKNOWN",
    )
    
    ###########################################################################
# URL Normalization
###########################################################################

def normalize_url(
    url: str,
):

    parsed = parse_url(url)

    scheme = parsed.scheme.lower()

    host = (

        parsed.hostname.lower()

        if parsed.hostname

        else ""

    )

    result = f"{scheme}://{host}"

    if parsed.port:

        result += f":{parsed.port}"

    result += parsed.path

    if parsed.query:

        result += f"?{parsed.query}"

    return result

    ###########################################################################
# Socket Family
###########################################################################

def socket_family(
    host: str,
):

    try:

        info = socket.getaddrinfo(

            host,

            None,

        )

        if info:

            family = info[0][0]

            if family == socket.AF_INET:

                return "IPv4"

            if family == socket.AF_INET6:

                return "IPv6"

    except Exception:

        pass

    return "Unknown"


###########################################################################
# Serialization
###########################################################################

def endpoint_to_dict(
    endpoint: Endpoint,
):

    return {

        "host": endpoint.host,

        "port": endpoint.port,

        "protocol": endpoint.protocol,

        "service": common_service(
            endpoint.port
        ),

    }
    
    ###########################################################################
# Diagnostics
###########################################################################

def diagnostics():

    return {

        "hostname": local_hostname(),

        "local_ip": local_ip(),

        "supported_protocols": sorted(

            _PROTOCOLS

        ),

        "common_ports": len(

            _COMMON_PORTS

        ),

    }

    ###########################################################################
# Performance
###########################################################################

import time


def measure_dns(
    host: str,
):

    start = time.perf_counter()

    ip = resolve(host)

    elapsed = time.perf_counter() - start

    return {

        "host": host,

        "ip": ip,

        "elapsed": elapsed,

    }


def benchmark_dns(
    host: str,
    iterations: int = 100,
):

    start = time.perf_counter()

    for _ in range(iterations):

        resolve(host)

    return time.perf_counter() - start

###########################################################################
# Self Test
###########################################################################

def self_test():

    return {

        "port_validation": is_valid_port(443),

        "protocol_validation": is_valid_protocol("https"),

        "url_validation": is_valid_url(

            "https://example.com"

        ),

        "mac_validation": is_valid_mac(

            "AA:BB:CC:DD:EE:FF"

        ),

    }
    
    ###########################################################################
# Convenience
###########################################################################

def describe_endpoint(
    host: str,
    port: int,
):

    return {

        "host": host,

        "resolved_ip": resolve(host),

        "port": port,

        "service": common_service(port),

        "reachable": is_port_open(

            host,

            port,

            timeout=1,

        ),

    }
    
    