from __future__ import annotations

import logging
from dataclasses import field
from pathlib import Path
from typing import Any, TypedDict, cast

from attackcti import attack_client  # type: ignore[reportMissingTypeStubs]
from pydantic import BaseModel

from contentctl.objects.annotated_types import MITRE_ATTACK_ID_TYPE
from contentctl.objects.config import validate
from contentctl.objects.mitre_attack_enrichment import (
    MitreAttackEnrichment,
    MitreTactics,
)

# Suppress attackcti logging
logging.getLogger("taxii2client").setLevel(logging.CRITICAL)
logging.getLogger("stix2").setLevel(logging.CRITICAL)


class AttackPattern(TypedDict):
    id: str
    technique_id: str
    technique: str
    tactic: list[str]


class IntrusionSet(TypedDict):
    id: str
    group: str


class Relationship(TypedDict):
    target_object: str
    source_object: str


class AttackEnrichment(BaseModel):
    data: dict[str, MitreAttackEnrichment] = field(default_factory=dict)
    use_enrichment: bool = True

    @staticmethod
    def getAttackEnrichment(config: validate) -> AttackEnrichment:
        enrichment = AttackEnrichment(use_enrichment=config.enrichments)
        _ = enrichment.get_attack_lookup(config.mitre_cti_repo_path, config.enrichments)
        return enrichment

    def getEnrichmentByMitreID(
        self, mitre_id: MITRE_ATTACK_ID_TYPE
    ) -> MitreAttackEnrichment:
        if not self.use_enrichment:
            raise Exception(
                "Error, trying to add Mitre Enrichment, but use_enrichment was set to False"
            )

        enrichment = self.data.get(mitre_id, None)
        if enrichment is not None:
            return enrichment
        else:
            raise Exception(
                f"Error, Unable to find Mitre Enrichment for MitreID {mitre_id}"
            )

    def addMitreIDViaGroupNames(
        self, technique: dict[str, Any], tactics: list[str], groupNames: list[str]
    ) -> None:
        technique_id = technique["technique_id"]
        technique_obj = technique["technique"]
        tactics.sort()

        if technique_id in self.data:
            raise Exception(f"Error, trying to redefine MITRE ID '{technique_id}'")
        self.data[technique_id] = MitreAttackEnrichment.model_validate(
            {
                "mitre_attack_id": technique_id,
                "mitre_attack_technique": technique_obj,
                "mitre_attack_tactics": tactics,
                "mitre_attack_groups": groupNames,
                "mitre_attack_group_objects": [],
            }
        )

    def addMitreIDViaGroupObjects(
        self,
        technique: dict[str, Any],
        tactics: list[MitreTactics],
        groupDicts: list[dict[str, Any]],
    ) -> None:
        technique_id = technique["technique_id"]
        technique_obj = technique["technique"]
        tactics.sort()

        groupNames: list[str] = sorted([group["group"] for group in groupDicts])

        if technique_id in self.data:
            raise Exception(f"Error, trying to redefine MITRE ID '{technique_id}'")

        self.data[technique_id] = MitreAttackEnrichment.model_validate(
            {
                "mitre_attack_id": technique_id,
                "mitre_attack_technique": technique_obj,
                "mitre_attack_tactics": tactics,
                "mitre_attack_groups": groupNames,
                "mitre_attack_group_objects": groupDicts,
            }
        )

    def get_attack_lookup(
        self, input_path: Path, enrichments: bool = False
    ) -> dict[str, MitreAttackEnrichment]:
        attack_lookup: dict[str, MitreAttackEnrichment] = {}
        if not enrichments:
            return attack_lookup

        try:
            print(
                f"Performing MITRE Enrichment using the repository at {input_path}...",
                end="",
                flush=True,
            )
            enterprise_path = input_path / "enterprise-attack"
            mobile_path = input_path / "ics-attack"
            ics_path = input_path / "mobile-attack"
            if not (
                enterprise_path.is_dir() and mobile_path.is_dir() and ics_path.is_dir()
            ):
                raise FileNotFoundError(
                    "One or more of the following paths does not exist: "
                    f"{[str(enterprise_path), str(mobile_path), str(ics_path)]}. "
                    f"Please ensure that the {input_path} directory "
                    "has been git cloned correctly."
                )
            lift = attack_client(
                local_paths={
                    "enterprise": str(enterprise_path),
                    "mobile": str(mobile_path),
                    "ics": str(ics_path),
                }
            )

            all_enterprise_techniques = cast(
                list[AttackPattern], lift.get_enterprise_techniques(stix_format=False)
            )
            enterprise_relationships = cast(
                list[Relationship], lift.get_enterprise_relationships(stix_format=False)
            )
            enterprise_groups = cast(
                list[IntrusionSet], lift.get_enterprise_groups(stix_format=False)
            )

            for technique in all_enterprise_techniques:
                apt_groups: list[dict[str, Any]] = []
                for relationship in enterprise_relationships:
                    if relationship["target_object"] == technique[
                        "id"
                    ] and relationship["source_object"].startswith("intrusion-set"):
                        for group in enterprise_groups:
                            if relationship["source_object"] == group["id"]:
                                apt_groups.append(dict(group))

                tactics: list[MitreTactics] = []
                if "tactic" in technique:
                    for tactic in technique["tactic"]:
                        tactics.append(
                            cast(MitreTactics, tactic.replace("-", " ").title())
                        )

                self.addMitreIDViaGroupObjects(dict(technique), tactics, apt_groups)
                attack_lookup[technique["technique_id"]] = (
                    MitreAttackEnrichment.model_validate(
                        {
                            "mitre_attack_id": technique["technique_id"],
                            "mitre_attack_technique": technique["technique"],
                            "mitre_attack_tactics": tactics,
                            "mitre_attack_groups": [
                                group["group"] for group in apt_groups
                            ],
                            "mitre_attack_group_objects": apt_groups,
                        }
                    )
                )

        except Exception as err:
            raise Exception(f"Error getting MITRE Enrichment: {str(err)}")

        print("Done!")
        return attack_lookup
