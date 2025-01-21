from __future__ import annotations
from pydantic import BaseModel, ConfigDict
from typing import List


class DeploymentNotable(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rule_description: str
    rule_title: str
    nes_fields: List[str]
