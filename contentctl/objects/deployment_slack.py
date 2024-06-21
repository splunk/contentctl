from __future__ import annotations
from pydantic import BaseModel


class DeploymentSlack(BaseModel):
    channel: str
    message: str
    webhook_url: str
    fields: str
