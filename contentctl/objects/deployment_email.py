from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict


class DeploymentEmail(BaseModel):
    model_config = ConfigDict(extra="forbid")
    message: str
    subject: str
    to: str
    sendcsv: Optional[bool] = False
