"""
IP Address Utilities

Enterprise-grade utilities for

• IPv4
• IPv6
• CIDR
• Private/Public
• Multicast
• Reserved
• Validation
"""

from __future__ import annotations

import ipaddress

from typing import Any


###########################################################################
# Validation
###########################################################################

def is_valid_ip(
    value: str,
) -> bool:

    try:

        ipaddress.ip_address(value)

        return True

    except ValueError:

        return False


def is_valid_network(
    value: str,
) -> bool:

    try:

        ipaddress.ip_network(
            value,
            strict=False,
        )

        return True

    except ValueError:

        return False


###########################################################################
# Parsing
###########################################################################

def parse_ip(
    value: str,
):

    return ipaddress.ip_address(
        value
    )


def parse_network(
    value: str,
):

    return ipaddress.ip_network(
        value,
        strict=False,
    )
    ###########################################################################
# Properties
###########################################################################

def version(
    ip: str,
) -> int:

    return parse_ip(ip).version


def is_ipv4(
    ip: str,
) -> bool:

    return version(ip) == 4


def is_ipv6(
    ip: str,
) -> bool:

    return version(ip) == 6


def is_private(
    ip: str,
) -> bool:

    return parse_ip(ip).is_private


def is_public(
    ip: str,
) -> bool:

    return not parse_ip(ip).is_private


def is_loopback(
    ip: str,
) -> bool:

    return parse_ip(ip).is_loopback


def is_multicast(
    ip: str,
) -> bool:

    return parse_ip(ip).is_multicast


def is_reserved(
    ip: str,
) -> bool:

    return parse_ip(ip).is_reserved


def is_link_local(
    ip: str,
) -> bool:

    return parse_ip(ip).is_link_local
###########################################################################
# Network
###########################################################################

def network_address(
    cidr: str,
):

    return str(

        parse_network(
            cidr
        ).network_address

    )


def broadcast_address(
    cidr: str,
):

    network = parse_network(
        cidr
    )

    if network.version == 6:

        return None

    return str(
        network.broadcast_address
    )


def prefix_length(
    cidr: str,
) -> int:

    return parse_network(
        cidr
    ).prefixlen


def subnet_mask(
    cidr: str,
):

    return str(

        parse_network(
            cidr
        ).netmask

    )


def host_mask(
    cidr: str,
):

    return str(

        parse_network(
            cidr
        ).hostmask

    )
    
    ###########################################################################
# Membership
###########################################################################

def contains(
    cidr: str,
    ip: str,
) -> bool:

    return parse_ip(ip) in parse_network(
        cidr
    )


def overlaps(
    first: str,
    second: str,
) -> bool:

    return parse_network(
        first
    ).overlaps(

        parse_network(
            second
        )

    )
    ###########################################################################
# Conversion
###########################################################################

def to_integer(
    ip: str,
) -> int:

    return int(
        parse_ip(ip)
    )


def from_integer(
    value: int,
):

    return str(

        ipaddress.ip_address(
            value
        )

    )


def compressed(
    ip: str,
):

    return parse_ip(
        ip
    ).compressed


def exploded(
    ip: str,
):

    return parse_ip(
        ip
    ).exploded
    
    ###########################################################################
# CIDR Summarization
###########################################################################

def summarize(
    first: str,
    last: str,
):

    start = parse_ip(first)

    end = parse_ip(last)

    return [

        str(network)

        for network in ipaddress.summarize_address_range(
            start,
            end,
        )

    ]


###########################################################################
# Supernet
###########################################################################

def supernet(
    cidr: str,
    prefix_diff: int = 1,
):

    return str(

        parse_network(cidr).supernet(

            prefixlen_diff=prefix_diff,

        )

    )


###########################################################################
# Subnets
###########################################################################

def subnets(
    cidr: str,
    prefix_diff: int = 1,
):

    return [

        str(network)

        for network in parse_network(cidr).subnets(

            prefixlen_diff=prefix_diff,

        )

    ]


###########################################################################
# Reverse DNS
###########################################################################

def reverse_pointer(
    ip: str,
):

    return parse_ip(ip).reverse_pointer


###########################################################################
# Range
###########################################################################

def ip_range(
    cidr: str,
):

    return [

        str(ip)

        for ip in parse_network(cidr).hosts()

    ]


###########################################################################
# Neighbor Addresses
###########################################################################

def previous_ip(
    ip: str,
):

    return str(

        parse_ip(ip) - 1

    )


def next_ip(
    ip: str,
):

    return str(

        parse_ip(ip) + 1

    )


###########################################################################
# RFC1918
###########################################################################

def is_rfc1918(
    ip: str,
) -> bool:

    address = parse_ip(ip)

    return (

        address in ipaddress.ip_network("10.0.0.0/8")

        or

        address in ipaddress.ip_network("172.16.0.0/12")

        or

        address in ipaddress.ip_network("192.168.0.0/16")

    )


###########################################################################
# Classification
###########################################################################

def classify(
    ip: str,
) -> str:

    address = parse_ip(ip)

    if address.is_loopback:

        return "Loopback"

    if address.is_multicast:

        return "Multicast"

    if address.is_link_local:

        return "Link Local"

    if address.is_reserved:

        return "Reserved"

    if address.is_private:

        return "Private"

    return "Public"


###########################################################################
# Batch Validation
###########################################################################

def validate_many(
    addresses: list[str],
):

    return {

        ip: is_valid_ip(ip)

        for ip in addresses

    }


###########################################################################
# Batch Classification
###########################################################################

def classify_many(
    addresses: list[str],
):

    return {

        ip: classify(ip)

        for ip in addresses

    }


###########################################################################
# Batch Membership
###########################################################################

def contains_many(
    cidr: str,
    addresses: list[str],
):

    network = parse_network(cidr)

    return {

        ip: parse_ip(ip) in network

        for ip in addresses

    }


###########################################################################
# Threat Intelligence Helper
###########################################################################

def normalize_ip(
    ip: str,
):

    return parse_ip(ip).compressed


###########################################################################
# Address Family
###########################################################################

def family(
    ip: str,
):

    return "IPv4" if is_ipv4(ip) else "IPv6"

###########################################################################
# Host Count
###########################################################################

def host_count(
    cidr: str,
) -> int:

    network = parse_network(cidr)

    if network.version == 4:

        if network.prefixlen >= 31:
            return network.num_addresses

        return max(network.num_addresses - 2, 0)

    return network.num_addresses


###########################################################################
# Network Size
###########################################################################

def network_size(
    cidr: str,
) -> int:

    return parse_network(
        cidr
    ).num_addresses


###########################################################################
# First Host
###########################################################################

def first_host(
    cidr: str,
):

    network = parse_network(cidr)

    if network.version == 6:

        return str(network.network_address)

    hosts = list(network.hosts())

    if not hosts:

        return str(network.network_address)

    return str(hosts[0])


###########################################################################
# Last Host
###########################################################################

def last_host(
    cidr: str,
):

    network = parse_network(cidr)

    if network.version == 6:

        return str(network.broadcast_address)

    hosts = list(network.hosts())

    if not hosts:

        return str(network.broadcast_address)

    return str(hosts[-1])


###########################################################################
# Sort Addresses
###########################################################################

def sort_ips(
    addresses: list[str],
):

    return sorted(

        addresses,

        key=lambda ip: parse_ip(ip),

    )


###########################################################################
# Remove Duplicates
###########################################################################

def unique_ips(
    addresses: list[str],
):

    return list(

        dict.fromkeys(

            normalize_ip(ip)

            for ip in addresses

        )

    )


###########################################################################
# Serialization
###########################################################################

def to_dict(
    ip: str,
):

    address = parse_ip(ip)

    return {

        "ip": str(address),

        "compressed": address.compressed,

        "version": address.version,

        "private": address.is_private,

        "loopback": address.is_loopback,

        "multicast": address.is_multicast,

        "reserved": address.is_reserved,

        "link_local": address.is_link_local,

    }


###########################################################################
# Utility Predicates
###########################################################################

def same_network(
    ip1: str,
    ip2: str,
    prefix: int,
) -> bool:

    network1 = ipaddress.ip_network(
        f"{ip1}/{prefix}",
        strict=False,
    )

    network2 = ipaddress.ip_network(
        f"{ip2}/{prefix}",
        strict=False,
    )

    return network1.network_address == network2.network_address


def same_version(
    ip1: str,
    ip2: str,
) -> bool:

    return version(ip1) == version(ip2)


###########################################################################
# Performance Helper
###########################################################################

def normalize_many(
    addresses: list[str],
):

    return [

        normalize_ip(ip)

        for ip in addresses

    ]


###########################################################################
# Safe Parsing
###########################################################################

def safe_parse(
    ip: str,
):

    try:

        return parse_ip(ip)

    except ValueError:

        return None


###########################################################################
# Summary
###########################################################################

def summary(
    ip: str,
):

    return {

        "address": ip,

        "family": family(ip),

        "classification": classify(ip),

        "private": is_private(ip),

        "public": is_public(ip),

        "loopback": is_loopback(ip),

        "multicast": is_multicast(ip),

        "reserved": is_reserved(ip),

        "integer": to_integer(ip),

        "reverse_dns": reverse_pointer(ip),

    }
    
    