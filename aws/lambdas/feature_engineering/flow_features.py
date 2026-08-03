"""
Flow-derived Feature Engineering

Compute features constructed from raw network flow columns
commonly present in CICIDS2017 CSVs. This module is defensive
and tolerates missing columns by providing safe defaults.
"""
from __future__ import annotations

from typing import Dict, Any

# Common raw column name mappings (lowercase -> canonical)
FLOW_KEYS = {
    "flow duration": "flow_duration",
    "flowduration": "flow_duration",
    "total fwd packets": "total_fwd_packets",
    "total backward packets": "total_bwd_packets",
    "total bwd packets": "total_bwd_packets",
    "total length of fwd packets": "total_fwd_bytes",
    "total length of bwd packets": "total_bwd_bytes",
    "fwd packet length mean": "fwd_pkt_len_mean",
    "bwd packet length mean": "bwd_pkt_len_mean",
    "flow iat mean": "flow_iat_mean",
    "flow iat min": "flow_iat_min",
    "flow iat max": "flow_iat_max",
    "packet length mean": "packet_length_mean",
    "packet length std": "packet_length_std",
    "fwd header length": "fwd_header_len",
}


def _get_value(src: Dict[str, Any], keys: list, default=0.0):
    for k in keys:
        if k in src and src[k] is not None:
            try:
                return float(src[k])
            except Exception:
                return default
    return default


def generate_flow_features(event: Dict[str, Any]) -> Dict[str, float]:
    # Lowercase keys mapping for robustness
    lc = {str(k).strip().lower(): v for k, v in event.items()}

    # Flow duration (CICIDS often encodes microseconds)
    duration_us = _get_value(lc, ["flow duration", "flowduration", "flow_duration"], default=0.0)
    flow_duration_seconds = duration_us / 1_000_000.0 if duration_us > 0 else 0.0

    # Packet counts
    total_fwd_packets = _get_value(lc, ["total fwd packets", "total_fwd_packets", "total fwd packets"], default=0.0)
    total_bwd_packets = _get_value(lc, ["total backward packets", "total bwd packets", "total_bwd_packets"], default=0.0)
    total_packets = total_fwd_packets + total_bwd_packets

    # Bytes
    total_fwd_bytes = _get_value(lc, ["total length of fwd packets", "total_fwd_bytes", "total length of fwd packets"], default=0.0)
    total_bwd_bytes = _get_value(lc, ["total length of bwd packets", "total_bwd_bytes", "total length of bwd packets"], default=0.0)
    total_bytes = total_fwd_bytes + total_bwd_bytes

    # Packet/byte rates
    packets_per_second = (total_packets / flow_duration_seconds) if (flow_duration_seconds > 0 and total_packets > 0) else 0.0
    bytes_per_second = (total_bytes / flow_duration_seconds) if (flow_duration_seconds > 0 and total_bytes > 0) else 0.0

    # Average packet size
    avg_packet_size = (total_bytes / total_packets) if total_packets > 0 else 0.0

    # Forward/backward ratios
    fwd_bwd_packet_ratio = (total_fwd_packets / total_bwd_packets) if total_bwd_packets > 0 else (total_fwd_packets if total_fwd_packets > 0 else 0.0)
    fwd_bwd_byte_ratio = (total_fwd_bytes / total_bwd_bytes) if total_bwd_bytes > 0 else (total_fwd_bytes if total_fwd_bytes > 0 else 0.0)

    # Packet length means
    fwd_pkt_len_mean = _get_value(lc, ["fwd packet length mean", "fwd_pkt_len_mean"], default=0.0)
    bwd_pkt_len_mean = _get_value(lc, ["bwd packet length mean", "bwd_pkt_len_mean"], default=0.0)

    flow_iat_mean = _get_value(lc, ["flow iat mean", "flow_iat_mean"], default=0.0)

    packet_length_mean = _get_value(lc, ["packet length mean", "packet_length_mean"], default=0.0)
    packet_length_std = _get_value(lc, ["packet length std", "packet_length_std"], default=0.0)

    # TCP flag counts (best-effort: many datasets supply counts or flags)
    tcp_syn_count = _get_value(lc, ["syn flag count", "syn_flag_count", "syn_count"], default=0.0)
    tcp_ack_count = _get_value(lc, ["ack flag count", "ack_flag_count", "ack_count"], default=0.0)
    tcp_rst_count = _get_value(lc, ["rst flag count", "rst_flag_count", "rst_count"], default=0.0)
    tcp_fin_count = _get_value(lc, ["fin flag count", "fin_flag_count", "fin_count"], default=0.0)
    tcp_psh_count = _get_value(lc, ["psh flag count", "psh_flag_count", "psh_count"], default=0.0)
    tcp_urg_count = _get_value(lc, ["urg flag count", "urg_flag_count", "urg_count"], default=0.0)

    return {
        "flow_duration_seconds": flow_duration_seconds,
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "fwd_packets": total_fwd_packets,
        "bwd_packets": total_bwd_packets,
        "fwd_bytes": total_fwd_bytes,
        "bwd_bytes": total_bwd_bytes,
        "packets_per_second": packets_per_second,
        "bytes_per_second": bytes_per_second,
        "avg_packet_size": avg_packet_size,
        "fwd_bwd_packet_ratio": fwd_bwd_packet_ratio,
        "fwd_bwd_byte_ratio": fwd_bwd_byte_ratio,
        "fwd_packet_len_mean": fwd_pkt_len_mean,
        "bwd_packet_len_mean": bwd_pkt_len_mean,
        "flow_iat_mean": flow_iat_mean,
        "packet_length_mean": packet_length_mean,
        "packet_length_std": packet_length_std,
        "inter_arrival_time_mean": flow_iat_mean,
        "tcp_syn_count": tcp_syn_count,
        "tcp_ack_count": tcp_ack_count,
        "tcp_rst_count": tcp_rst_count,
        "tcp_fin_count": tcp_fin_count,
        "tcp_psh_count": tcp_psh_count,
        "tcp_urg_count": tcp_urg_count,
    }
