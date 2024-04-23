from __future__ import annotations
from pydantic import BaseModel, Field, ConfigDict
from typing import Set,List,Annotated
from enum import StrEnum


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


class MitreAttackEnrichment(BaseModel):
    ConfigDict(use_enum_values=True)
    mitre_attack_id: Annotated[str, Field(pattern="^T\d{4}(.\d{3})?$")] = Field(...)
    mitre_attack_technique: str = Field(...)
    mitre_attack_tactics: List[MitreTactics] = Field(...)
    mitre_attack_groups: List[str] = Field(...)

    def __hash__(self) -> int:
        return id(self)