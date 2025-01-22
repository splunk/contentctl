from __future__ import annotations
from pydantic import BaseModel, ConfigDict


class DeploymentScheduling(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cron_schedule: str
    earliest_time: str
    latest_time: str
    schedule_window: str
