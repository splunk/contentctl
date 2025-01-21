from __future__ import annotations
from pydantic import BaseModel, ConfigDict


class DeploymentRBA(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
