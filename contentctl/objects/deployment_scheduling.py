from __future__ import annotations
from pydantic import BaseModel


class DeploymentScheduling(BaseModel):
    cron_schedule: str
    earliest_time: str
    latest_time: str
    schedule_window: str