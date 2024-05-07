from __future__ import annotations
from pydantic import BaseModel


class DeploymentRBA(BaseModel):
    enabled: bool = False