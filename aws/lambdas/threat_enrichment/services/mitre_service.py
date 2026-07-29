"""
Enterprise MITRE ATT&CK Service

Provides MITRE ATT&CK enrichment.

Features
--------
• ATT&CK Enterprise Matrix
• Tactics
• Techniques
• Sub-Techniques
• Groups
• Software
• Mitigations
• Relationships
• Fast Lookups
• ATT&CK Graph Traversal
• Threat Event Enrichment

Python 3.11+
"""

from __future__ import annotations

import asyncio
import json

from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from typing import Any

from ..exceptions import MITRELookupError
from ..logger import get_logger

from ..models.mitre import (
    MITREMapping,
    TacticModel,
    TechniqueModel,
    SubTechniqueModel,
    ThreatGroupModel,
    SoftwareModel,
)

from .base_service import BaseService


class MITREService(BaseService):

    service_name = "MITREService"

    ####################################################################
    # Initialization
    ####################################################################

    def __init__(
        self,
        attack_directory: str | Path | None = None,
    ) -> None:

        super().__init__()

        self.logger = get_logger("MITREService")

        self.lock = Lock()

        self.attack_directory = (
            Path(attack_directory)
            if attack_directory
            else Path("data/mitre")
        )

        ###############################################################
        # Storage
        ###############################################################

        self.tactics: list[TacticModel] = []

        self.techniques: list[TechniqueModel] = []

        self.subtechniques: list[SubTechniqueModel] = []

        self.groups: list[ThreatGroupModel] = []

        self.software: list[SoftwareModel] = []

        ###############################################################
        # Fast Indexes
        ###############################################################

        self.tactic_index: dict[
            str,
            TacticModel,
        ] = {}

        self.technique_index: dict[
            str,
            TechniqueModel,
        ] = {}

        self.subtechnique_index: dict[
            str,
            SubTechniqueModel,
        ] = {}

        self.group_index: dict[
            str,
            ThreatGroupModel,
        ] = {}

        self.software_index: dict[
            str,
            SoftwareModel,
        ] = {}

        ###############################################################
        # Relationship Graph
        ###############################################################

        self.technique_to_tactic = defaultdict(list)

        self.tactic_to_techniques = defaultdict(list)

        self.group_to_techniques = defaultdict(list)

        self.software_to_techniques = defaultdict(list)

        self.technique_to_groups = defaultdict(list)

        self.technique_to_software = defaultdict(list)

        ###############################################################
        # Cache
        ###############################################################

        self.lookup_cache: dict[str, Any] = {}

        ###############################################################
        # Metadata
        ###############################################################

        self.loaded_at = None

        self.feed_count = 0

        ###############################################################
        # Statistics
        ###############################################################

        self.stats_data = {

            "tactics": 0,

            "techniques": 0,

            "subtechniques": 0,

            "groups": 0,

            "software": 0,

            "relationships": 0,

            "lookups": 0,

            "hits": 0,

            "misses": 0,
        }

    ####################################################################
    # Initialize
    ####################################################################

    def initialize(self):

        super().initialize()

        self.load_attack_data()

    ####################################################################
    # Feed Discovery
    ####################################################################

    def discover_files(self):

        if not self.attack_directory.exists():

            return []

        return sorted(

            self.attack_directory.glob(
                "*.json"
            )

        )

    ####################################################################
    # Load ATT&CK
    ####################################################################

    def load_attack_data(self):

        files = self.discover_files()

        self.feed_count = len(files)

        for file in files:

            self.load_file(file)

        self.loaded_at = datetime.now(UTC)

    ####################################################################
    # Load File
    ####################################################################

    def load_file(
        self,
        path: Path,
    ):

        with open(
            path,
            encoding="utf-8",
        ) as fp:

            attack = json.load(fp)

        objects = attack.get(
            "objects",
            [],
        )

        for obj in objects:

            self.process_object(obj)
        ####################################################################
    # Process STIX Object
    ####################################################################

    def process_object(
        self,
        obj: dict[str, Any],
    ) -> None:

        object_type = obj.get("type")

        if object_type == "x-mitre-tactic":
            self.add_tactic(obj)

        elif object_type == "attack-pattern":
            self.add_attack_pattern(obj)

        elif object_type == "intrusion-set":
            self.add_group(obj)

        elif object_type in (
            "tool",
            "malware",
        ):
            self.add_software(obj)

        elif object_type == "relationship":
            self.add_relationship(obj)

    ####################################################################
    # Add Tactic
    ####################################################################

    def add_tactic(
        self,
        obj: dict[str, Any],
    ) -> None:

        external = obj.get(
            "external_references",
            [],
        )

        tactic_id = ""

        for ref in external:

            if ref.get("source_name") == "mitre-attack":

                tactic_id = ref.get(
                    "external_id",
                    "",
                )

                break

        tactic = TacticModel(

            tactic_id=tactic_id,

            name=obj.get("name"),

            description=obj.get(
                "description",
            ),
        )

        self.tactics.append(tactic)

        self.tactic_index[
            tactic_id
        ] = tactic

        self.stats_data[
            "tactics"
        ] += 1

    ####################################################################
    # Add Technique / Sub-Technique
    ####################################################################

    def add_attack_pattern(
        self,
        obj: dict[str, Any],
    ) -> None:

        external = obj.get(
            "external_references",
            [],
        )

        technique_id = ""

        for ref in external:

            if ref.get("source_name") == "mitre-attack":

                technique_id = ref.get(
                    "external_id",
                    "",
                )

                break

        is_sub = obj.get(
            "x_mitre_is_subtechnique",
            False,
        )

        if is_sub:

            technique = SubTechniqueModel(

                technique_id=technique_id,

                name=obj.get("name"),

                description=obj.get(
                    "description",
                ),
            )

            self.subtechniques.append(
                technique,
            )

            self.subtechnique_index[
                technique_id
            ] = technique

            self.stats_data[
                "subtechniques"
            ] += 1

        else:

            technique = TechniqueModel(

                technique_id=technique_id,

                name=obj.get("name"),

                description=obj.get(
                    "description",
                ),
            )

            self.techniques.append(
                technique,
            )

            self.technique_index[
                technique_id
            ] = technique

            self.stats_data[
                "techniques"
            ] += 1

    ####################################################################
    # Add Threat Group
    ####################################################################

    def add_group(
        self,
        obj: dict[str, Any],
    ) -> None:

        external = obj.get(
            "external_references",
            [],
        )

        group_id = ""

        for ref in external:

            if ref.get("source_name") == "mitre-attack":

                group_id = ref.get(
                    "external_id",
                    "",
                )

                break

        group = ThreatGroupModel(

            group_id=group_id,

            name=obj.get("name"),

            description=obj.get(
                "description",
            ),
        )

        self.groups.append(group)

        self.group_index[
            group_id
        ] = group

        self.stats_data[
            "groups"
        ] += 1

    ####################################################################
    # Add Software
    ####################################################################

    def add_software(
        self,
        obj: dict[str, Any],
    ) -> None:

        external = obj.get(
            "external_references",
            [],
        )

        software_id = ""

        for ref in external:

            if ref.get("source_name") == "mitre-attack":

                software_id = ref.get(
                    "external_id",
                    "",
                )

                break

        software = SoftwareModel(

            software_id=software_id,

            name=obj.get("name"),

            description=obj.get(
                "description",
            ),
        )

        self.software.append(
            software,
        )

        self.software_index[
            software_id
        ] = software

        self.stats_data[
            "software"
        ] += 1

    ####################################################################
    # Relationships
    ####################################################################

    def add_relationship(
        self,
        obj: dict[str, Any],
    ) -> None:

        relationship = obj.get(
            "relationship_type",
        )

        source = obj.get(
            "source_ref",
        )

        target = obj.get(
            "target_ref",
        )

        if not (
            relationship
            and source
            and target
        ):
            return

        self.stats_data[
            "relationships"
        ] += 1

        self._store_relationship(

            relationship,

            source,

            target,

        )

    ####################################################################
    # Relationship Storage
    ####################################################################

    def _store_relationship(

        self,

        relationship: str,

        source: str,

        target: str,

    ) -> None:

        if relationship == "uses":

            self.group_to_techniques[
                source
            ].append(target)

            self.software_to_techniques[
                source
            ].append(target)

            self.technique_to_groups[
                target
            ].append(source)

            self.technique_to_software[
                target
            ].append(source)

        elif relationship == "mitigates":

            pass

        elif relationship == "detects":

            pass
    ####################################################################
    # Lookup Technique
    ####################################################################

    def lookup_technique(
        self,
        technique_id: str,
    ) -> TechniqueModel | SubTechniqueModel | None:

        if not technique_id:
            return None

        technique_id = technique_id.upper().strip()

        self.stats_data["lookups"] += 1

        cached = self.lookup_cache.get(technique_id)

        if cached is not None:

            self.stats_data["hits"] += 1

            return cached

        result = (
            self.technique_index.get(technique_id)
            or self.subtechnique_index.get(technique_id)
        )

        if result:
            self.stats_data["hits"] += 1
        else:
            self.stats_data["misses"] += 1

        self.lookup_cache[technique_id] = result

        return result

    ####################################################################
    # Lookup Tactic
    ####################################################################

    def lookup_tactic(
        self,
        tactic_id: str,
    ) -> TacticModel | None:

        if not tactic_id:
            return None

        return self.tactic_index.get(
            tactic_id.upper()
        )

    ####################################################################
    # Lookup Threat Group
    ####################################################################

    def lookup_group(
        self,
        group_id: str,
    ) -> ThreatGroupModel | None:

        if not group_id:
            return None

        return self.group_index.get(
            group_id.upper()
        )

    ####################################################################
    # Lookup Software
    ####################################################################

    def lookup_software(
        self,
        software_id: str,
    ) -> SoftwareModel | None:

        if not software_id:
            return None

        return self.software_index.get(
            software_id.upper()
        )

    ####################################################################
    # Related Groups
    ####################################################################

    def related_groups(
        self,
        technique_id: str,
    ) -> list[ThreatGroupModel]:

        groups = []

        for gid in self.technique_to_groups.get(
            technique_id,
            [],
        ):

            group = self.lookup_group(gid)

            if group:

                groups.append(group)

        return groups

    ####################################################################
    # Related Software
    ####################################################################

    def related_software(
        self,
        technique_id: str,
    ) -> list[SoftwareModel]:

        software = []

        for sid in self.technique_to_software.get(
            technique_id,
            [],
        ):

            tool = self.lookup_software(sid)

            if tool:

                software.append(tool)

        return software

    ####################################################################
    # Techniques Used By Group
    ####################################################################

    def group_techniques(
        self,
        group_id: str,
    ) -> list[TechniqueModel]:

        results = []

        for tid in self.group_to_techniques.get(
            group_id,
            [],
        ):

            tech = self.lookup_technique(tid)

            if tech:

                results.append(tech)

        return results

    ####################################################################
    # Techniques Used By Software
    ####################################################################

    def software_techniques(
        self,
        software_id: str,
    ) -> list[TechniqueModel]:

        results = []

        for tid in self.software_to_techniques.get(
            software_id,
            [],
        ):

            tech = self.lookup_technique(tid)

            if tech:

                results.append(tech)

        return results

    ####################################################################
    # ATT&CK Mapping
    ####################################################################

    def create_mapping(
        self,
        technique_id: str,
    ) -> MITREMapping | None:

        technique = self.lookup_technique(
            technique_id
        )

        if not technique:

            return None

        return MITREMapping(

            technique=technique,

            tactics=[],

            groups=self.related_groups(
                technique_id
            ),

            software=self.related_software(
                technique_id
            ),
        )

    ####################################################################
    # Batch Mapping
    ####################################################################

    def create_mappings(
        self,
        techniques: list[str],
    ) -> list[MITREMapping]:

        mappings = []

        for tid in techniques:

            mapping = self.create_mapping(
                tid
            )

            if mapping:

                mappings.append(mapping)

        return mappings

    ####################################################################
    # Event Enrichment
    ####################################################################

    def enrich_event(
        self,
        event,
    ):

        if not getattr(
            event,
            "techniques",
            None,
        ):

            return event

        event.mitre = self.create_mappings(
            event.techniques
        )

        return event
        ####################################################################
    # Search Techniques
    ####################################################################

    def search_techniques(
        self,
        keyword: str,
    ) -> list[TechniqueModel]:

        if not keyword:
            return []

        keyword = keyword.lower()

        results = []

        for technique in self.techniques:

            if (
                keyword in technique.name.lower()
                or keyword in (
                    technique.description or ""
                ).lower()
            ):
                results.append(technique)

        return results

    ####################################################################
    # Search Groups
    ####################################################################

    def search_groups(
        self,
        keyword: str,
    ) -> list[ThreatGroupModel]:

        if not keyword:
            return []

        keyword = keyword.lower()

        results = []

        for group in self.groups:

            if (
                keyword in group.name.lower()
                or keyword in (
                    group.description or ""
                ).lower()
            ):
                results.append(group)

        return results

    ####################################################################
    # Search Software
    ####################################################################

    def search_software(
        self,
        keyword: str,
    ) -> list[SoftwareModel]:

        if not keyword:
            return []

        keyword = keyword.lower()

        results = []

        for software in self.software:

            if (
                keyword in software.name.lower()
                or keyword in (
                    software.description or ""
                ).lower()
            ):
                results.append(software)

        return results

    ####################################################################
    # Graph Statistics
    ####################################################################

    def graph_statistics(self) -> dict[str, int]:

        return {

            "tactics":
                len(self.tactics),

            "techniques":
                len(self.techniques),

            "subtechniques":
                len(self.subtechniques),

            "groups":
                len(self.groups),

            "software":
                len(self.software),

            "group_links":
                sum(
                    len(v)
                    for v in self.group_to_techniques.values()
                ),

            "software_links":
                sum(
                    len(v)
                    for v in self.software_to_techniques.values()
                ),
        }

    ####################################################################
    # Clear Cache
    ####################################################################

    def clear_cache(self):

        self.lookup_cache.clear()

    ####################################################################
    # Export
    ####################################################################

    def export_json(
        self,
        path: str | Path,
    ) -> None:

        path = Path(path)

        data = {

            "tactics":
                [
                    t.model_dump(mode="json")
                    for t in self.tactics
                ],

            "techniques":
                [
                    t.model_dump(mode="json")
                    for t in self.techniques
                ],

            "subtechniques":
                [
                    t.model_dump(mode="json")
                    for t in self.subtechniques
                ],

            "groups":
                [
                    g.model_dump(mode="json")
                    for g in self.groups
                ],

            "software":
                [
                    s.model_dump(mode="json")
                    for s in self.software
                ],
        }

        with open(
            path,
            "w",
            encoding="utf-8",
        ) as fp:

            json.dump(
                data,
                fp,
                indent=4,
                ensure_ascii=False,
            )

    ####################################################################
    # Import
    ####################################################################

    def import_json(
        self,
        path: str | Path,
    ) -> None:

        path = Path(path)

        with open(
            path,
            encoding="utf-8",
        ) as fp:

            data = json.load(fp)

        for row in data.get("tactics", []):

            self.tactics.append(
                TacticModel(**row)
            )

        for row in data.get("techniques", []):

            self.techniques.append(
                TechniqueModel(**row)
            )

        for row in data.get("subtechniques", []):

            self.subtechniques.append(
                SubTechniqueModel(**row)
            )

        for row in data.get("groups", []):

            self.groups.append(
                ThreatGroupModel(**row)
            )

        for row in data.get("software", []):

            self.software.append(
                SoftwareModel(**row)
            )

    ####################################################################
    # Refresh
    ####################################################################

    def refresh(self):

        self.clear_cache()

        self.load_attack_data()

    ####################################################################
    # Async Refresh
    ####################################################################

    async def async_refresh(self):

        loop = asyncio.get_running_loop()

        await loop.run_in_executor(
            None,
            self.refresh,
        )

    ####################################################################
    # Statistics
    ####################################################################

    def stats(self):

        return {

            "service":
                self.service_name,

            "loaded":
                (
                    len(self.tactics)
                    + len(self.techniques)
                    + len(self.groups)
                    + len(self.software)
                ),

            "cache":
                len(self.lookup_cache),

            **self.stats_data,
        }

    ####################################################################
    # Health
    ####################################################################

    def health(self):

        return {

            "status":
                "healthy",

            "loaded_at":
                self.loaded_at.isoformat()
                if self.loaded_at
                else None,

            "cache":
                len(self.lookup_cache),

            "graph":
                self.graph_statistics(),
        }

    ####################################################################
    # Process
    ####################################################################

    def process(
        self,
        techniques: list[str],
    ) -> list[MITREMapping]:

        return self.create_mappings(
            techniques
        )

    ####################################################################
    # Shutdown
    ####################################################################

    def shutdown(self):

        self.clear_cache()

        super().shutdown()

    ####################################################################
    # Magic Methods
    ####################################################################

    def __len__(self):

        return len(self.techniques)

    def __contains__(
        self,
        technique_id: str,
    ):

        return (
            self.lookup_technique(
                technique_id
            )
            is not None
        )

    def __repr__(self):

        return (
            f"<MITREService "
            f"techniques={len(self.techniques)} "
            f"groups={len(self.groups)}>"
        )
    