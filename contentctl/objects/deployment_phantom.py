from __future__ import annotations
from pydantic import BaseModel


class DeploymentPhantom(BaseModel):
    cam_workers : str
    label : str
    phantom_server : str
    sensitivity : str
    severity : str