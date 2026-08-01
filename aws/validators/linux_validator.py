"""
Linux Event Validator

Validates Linux audit logs, Syslog and Sysmon for Linux
and converts them into the canonical ThreatEvent model.

Supported Sources
-----------------
• auditd
• syslog
• auth.log
• secure
• journald
• Sysmon for Linux

Author: AI-Assisted Threat Detection Dashboard
Python 3.11+
"""

from __future__ import annotations

from typing import Any

from ..models.asset import AssetModel
from ..models.event import (
    EventCategory,
    EventSource,
    ThreatEvent,
)
from ..models.user import UserModel
from .event_validator import EventValidator


class LinuxValidator(EventValidator):

    validator_name = "LinuxValidator"

    # ============================================================
    # Main Validation
    # ============================================================

    def validate(
        self,
        raw_event: dict[str, Any],
    ) -> ThreatEvent:

        event = super().validate(raw_event)

        event.event_source = EventSource.LINUX

        event.asset = self.build_asset(raw_event)

        event.user = self.build_user(raw_event)

        event.category = self.detect_category(raw_event)

        self.extract_linux_metadata(
            event,
            raw_event,
        )

        return event

    # ============================================================
    # Asset
    # ============================================================

    def build_asset(
        self,
        data: dict[str, Any],
    ) -> AssetModel:

        return AssetModel(
            hostname=data.get("hostname"),
            operating_system="Linux",
            asset_name=data.get(
                "hostname",
                "Unknown",
            ),
            owner=data.get("owner"),
            department=data.get("department"),
            environment=data.get(
                "environment",
                "PRODUCTION",
            ),
        )

    # ============================================================
    # User
    # ============================================================

    def build_user(
        self,
        data: dict[str, Any],
    ) -> UserModel:

        return UserModel(
            username=data.get("username"),
            email=data.get("email"),
            role=data.get("role"),
            department=data.get("department"),
        )

    # ============================================================
    # Category Detection
    # ============================================================

    def detect_category(
        self,
        data: dict[str, Any],
    ) -> EventCategory:

        audit_type = str(
            data.get(
                "audit_type",
                "",
            )
        ).upper()

        if audit_type in (
            "USER_LOGIN",
            "USER_AUTH",
        ):
            return EventCategory.AUTHENTICATION

        if audit_type in (
            "EXECVE",
            "PROCESS",
        ):
            return EventCategory.ENDPOINT

        if audit_type in (
            "SYSCALL",
            "PRIV_ESC",
        ):
            return EventCategory.PRIVILEGE_ESCALATION

        if audit_type in (
            "NETFILTER",
            "SOCKET",
        ):
            return EventCategory.NETWORK

        if audit_type in (
            "FILE",
            "PATH",
        ):
            return EventCategory.FILE

        return EventCategory.OTHER

    # ============================================================
    # Metadata
    # ============================================================

    def extract_linux_metadata(
        self,
        event: ThreatEvent,
        data: dict[str, Any],
    ) -> None:

        metadata = {
            "audit_id": data.get("audit_id"),
            "audit_type": data.get("audit_type"),
            "pid": data.get("pid"),
            "ppid": data.get("ppid"),
            "uid": data.get("uid"),
            "gid": data.get("gid"),
            "euid": data.get("euid"),
            "egid": data.get("egid"),
            "tty": data.get("tty"),
            "terminal": data.get("terminal"),
            "command": data.get("command"),
            "process_name": data.get("process_name"),
            "executable": data.get("executable"),
            "working_directory": data.get("cwd"),
            "selinux_context": data.get("selinux_context"),
        }

        for key, value in metadata.items():
            if value is not None:
                event.update_metadata(
                    key,
                    value,
                )

    # ============================================================
    # Linux Helpers
    # ============================================================

    @staticmethod
    def is_login_event(
        audit_type: str,
    ) -> bool:

        return audit_type.upper() in (
            "USER_LOGIN",
            "USER_AUTH",
        )

    @staticmethod
    def is_process_event(
        audit_type: str,
    ) -> bool:

        return audit_type.upper() in (
            "EXECVE",
            "PROCESS",
        )

    @staticmethod
    def is_network_event(
        audit_type: str,
    ) -> bool:

        return audit_type.upper() in (
            "SOCKET",
            "NETFILTER",
        )

    @staticmethod
    def is_privilege_event(
        audit_type: str,
    ) -> bool:

        return audit_type.upper() in (
            "SYSCALL",
            "PRIV_ESC",
        )