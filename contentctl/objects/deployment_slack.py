from __future__ import annotations
from pydantic import BaseModel, ConfigDict


class DeploymentSlack(BaseModel):
    model_config = ConfigDict(extra="forbid")
    channel: str
    message: str