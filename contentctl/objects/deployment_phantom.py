from __future__ import annotations
from pydantic import BaseModel, ConfigDict


class DeploymentPhantom(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cam_workers: str
    label: str
    phantom_server: str
    sensitivity: str
    severity: str
