from __future__ import annotations
from pydantic import BaseModel, Field, ConfigDict, HttpUrl, computed_field, field_serializer
from enum import StrEnum
from contentctl.objects.annotated_types import MITRE_ATTACK_ID_TYPE


class AttackGroupMatrix(StrEnum):
    enterprise_attack = "enterprise-attack"
    ics_attack = "ics-attack"
    mobile_attack = "mobile-attack"


class AttackGroupType(StrEnum):
    intrusion_set = "intrusion-set"
    attack_pattern = "attack-pattern"
    relationship = "relationship"

    @field_serializer("url")
    def serialize_url(self, url: None | HttpUrl):
        if url is None:
            return None
        return str(url)


class MitreAbstract(BaseModel):
    model_config = ConfigDict(extra='ignore')
    id: str
    type: AttackGroupType
    url: None | HttpUrl

    @field_serializer("url")
    def serialize_url(self, url: None | HttpUrl):
        if url is None:
            return None
        return str(url)

class MitreTactic(StrEnum):
    collection = "collection"
    command_and_control = "command-and-control"
    credential_access = "credential-access"
    defense_evasion = "defense-evasion"
    discovery = "discovery"
    execution = "execution"
    exfiltration = "exfiltration"
    impact = "impact"
    initial_access = "initial-access"
    lateral_movement = "lateral-movement"
    persistence = "persistence"
    privilege_escalation = "privilege-escalation"
    reconnaissance = "reconnaissance"
    resource_development = "resource-development"

class MitreEnterpriseTechnique(MitreAbstract):
    model_config = ConfigDict(extra='ignore')
    tactic: list[MitreTactic]
    technique: str
    technique_description: str
    technique_id: MITRE_ATTACK_ID_TYPE
    groups: list[MitreAttackGroup] = []

    
    def __hash__(self) -> int:
        return id(self)
    
    def updateGroups(self, relationships:list[MitreEnterpriseRelationship], groups:list[MitreAttackGroup]) -> None:
        # We only care about intrusion-set
        intrusion_relationships = list(filter(lambda r: r.target_object == self.id, relationships))
        self.groups = [group for group in groups if group.id in [ir.source_object for ir in intrusion_relationships]]
        return None
    
    @property
    def mitre_attack_technique(self) -> str:
        return self.technique_id
    
    @property
    def mitre_attack_groups(self) -> list[str]:
        return [group.group for group in self.groups]
    
    @property
    def mitre_attack_id(self) -> MITRE_ATTACK_ID_TYPE:
        return self.technique_id
    
    @property
    def mitre_attack_tactics(self) -> list[str]:
        return [tactic.value.replace('-',' ').title() for tactic in self.tactic] 


class MitreEnterpriseRelationship(MitreAbstract):
    model_config = ConfigDict(extra='ignore')
    relationship: str
    relationship_description: None | str
    source_object: str
    target_object: str
    
           

class MitreAttackGroup(MitreAbstract):
    model_config = ConfigDict(extra='ignore')
    group: str
    group_aliases: list[str]
    group_description: str
    group_id: str


'''
# TODO (#266): disable the use_enum_values configuration
class MitreAttackEnrichment(BaseModel):
    ConfigDict(use_enum_values=True)
    mitre_attack_technique: MitreEnterpriseTechnique = Field(...)
    #Exclude this field from serialization - it is very large and not useful in JSON objects
    mitre_attack_group_objects: list[MitreAttackGroup] = Field(..., exclude=True)
    def _hash_(self) -> int:
        return id(self)
    
    @computed_field
    def mitre_attack_groups(self) -> list[str]:
        return [group.group for group in self.mitre_attack_group_objects]

    @computed_field
    def mitre_attack_id(self) -> MITRE_ATTACK_ID_TYPE:
        return self.mitre_attack_technique.id

    @computed_field
    def mitre_attack_tactics(self) -> list[str]:
        return [tactic.value.replace('-',' ').title() for tactic in self.mitre_attack_technique.tactic] 

# The following Enums are complete, but likely to change. Do we want to include them as enums,
# or just have this as a string field?

'''