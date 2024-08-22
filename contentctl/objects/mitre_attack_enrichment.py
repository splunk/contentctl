from __future__ import annotations
from pydantic import BaseModel, Field, ConfigDict, HttpUrl
from typing import List, Annotated
from enum import StrEnum
import datetime

class MitreTactics(StrEnum):
    RECONNAISSANCE = "Reconnaissance"
    RESOURCE_DEVELOPMENT = "Resource Development"
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    COMMAND_AND_CONTROL = "Command And Control"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"


class AttackGroupMatrix(StrEnum):
    mitre_attack = "mitre-attack"


class AttackGroupType(StrEnum):
    intrusion_set = "intrusion-set"

class MitreDomain(StrEnum):
    intrusion_set = "enterprise-attack"
    mobile_attack = "mobile-attack"
    ics_attack = "ics-attack"

class MitreExternalReference(BaseModel):
    model_config = ConfigDict(extra='forbid')
    source_name: str
    external_id: None | str = None 
    url: None | HttpUrl = None
    description: None | str = None


class MitreAttackGroup(BaseModel):
    model_config = ConfigDict(extra='forbid')
    created: datetime.datetime
    created_by_ref: str
    external_references: list[MitreExternalReference]
    group: str
    group_aliases: list[str]
    group_description: str
    id: str
    matrix: AttackGroupMatrix
    modified: datetime.datetime
    object_marking_refs: list[str]
    type: AttackGroupType
    url: HttpUrl
    x_mitre_attack_spec_version: None | str = None
    x_mitre_deprecated: None | bool = None
    x_mitre_domains: list[MitreDomain]
    x_mitre_modified_by_ref: str
    x_mitre_version: str
    contributors: list[str] = []


class MitreAttackEnrichment(BaseModel):
    ConfigDict(use_enum_values=True)
    mitre_attack_id: Annotated[str, Field(pattern=r"^T\d{4}(.\d{3})?$")] = Field(...)
    mitre_attack_technique: str = Field(...)
    mitre_attack_tactics: List[MitreTactics] = Field(...)
    mitre_attack_groups: List[str] = Field(...)
    #Exclude this field from serialization - it is very large and not useful in JSON objects
    mitre_attack_group_objects: list[MitreAttackGroup] = Field(..., exclude=True)
    def __hash__(self) -> int:
        return id(self)

