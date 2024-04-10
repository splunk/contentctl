from __future__ import annotations
from pydantic import BaseModel
from typing import List

class DeploymentNotable(BaseModel):
    rule_description: str
    rule_title: str
    nes_fields: List[str]