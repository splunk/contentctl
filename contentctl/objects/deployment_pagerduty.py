from __future__ import annotations
from pydantic import BaseModel

class DeploymentPagerDuty(BaseModel):
    pagerduty_description: str
    integration_url_override: str
