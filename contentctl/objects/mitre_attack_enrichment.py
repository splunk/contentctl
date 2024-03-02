from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Set,List

class MitreAttackEnrichment(BaseModel):
    mitre_attack_id: str = Field(...)
    mitre_attack_technique: str = Field(...)
    mitre_attack_tactics: List[str] = Field(...)
    mitre_attack_groups: List[str] = Field(...)
