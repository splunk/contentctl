from __future__ import annotations
from pydantic import BaseModel


class DeploymentEmail(BaseModel):
    message: str
    subject: str
    to: str