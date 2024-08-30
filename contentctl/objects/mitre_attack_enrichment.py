from __future__ import annotations
from pydantic import BaseModel, Field, ConfigDict, HttpUrl, field_validator
from typing import List, Annotated
from enum import StrEnum
import datetime
from contentctl.objects.annotated_types import MITRE_ATTACK_ID_TYPE

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
    enterprise_attack = "enterprise-attack"
    ics_attack = "ics-attack"
    mobile_attack = "mobile-attack"


class AttackGroupType(StrEnum):
    intrusion_set = "intrusion-set"

class MitreExternalReference(BaseModel):
    model_config = ConfigDict(extra='forbid')
    source_name: str
    external_id: None | str = None 
    url: None | HttpUrl = None
    description: None | str = None


class MitreAttackGroup(BaseModel):
    model_config = ConfigDict(extra='forbid')
    contributors: list[str] = []
    created: datetime.datetime
    created_by_ref: str
    external_references: list[MitreExternalReference]
    group: str
    group_aliases: list[str]
    group_description: str
    group_id: str
    id: str
    matrix: list[AttackGroupMatrix]
    mitre_attack_spec_version: None | str
    mitre_version: str
    #assume that if the deprecated field is not present, then the group is not deprecated
    mitre_deprecated: bool
    modified: datetime.datetime
    modified_by_ref: str
    object_marking_refs: list[str]
    type: AttackGroupType
    url: HttpUrl
    

    @field_validator("mitre_deprecated", mode="before")
    def standardize_mitre_deprecated(cls, mitre_deprecated:bool | None) -> bool:
        '''
        For some reason, the API will return either a bool for mitre_deprecated OR
        None. We simplify our typing by converting None to False, and assuming that
        if deprecated is None, then the group is not deprecated.
        '''
        if mitre_deprecated is None:
            return False
        return mitre_deprecated

    @field_validator("contributors", mode="before")
    def standardize_contributors(cls, contributors:list[str] | None) -> list[str]:
        '''
        For some reason, the API will return either a list of strings for contributors OR
        None. We simplify our typing by converting None to an empty list.
        '''
        if contributors is None:
            return []
        return contributors

# TODO (#266): disable the use_enum_values configuration
class MitreAttackEnrichment(BaseModel):
    ConfigDict(use_enum_values=True)
    mitre_attack_id: MITRE_ATTACK_ID_TYPE = Field(...)
    mitre_attack_technique: str = Field(...)
    mitre_attack_tactics: List[MitreTactics] = Field(...)
    mitre_attack_groups: List[str] = Field(...)
    #Exclude this field from serialization - it is very large and not useful in JSON objects
    mitre_attack_group_objects: list[MitreAttackGroup] = Field(..., exclude=True)
    def __hash__(self) -> int:
        return id(self)

