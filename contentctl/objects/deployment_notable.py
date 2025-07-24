from __future__ import annotations

from typing import List

from pydantic import BaseModel, ConfigDict


class DeploymentNotable(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rule_description: str
    rule_title: str
    nes_fields: List[str]
