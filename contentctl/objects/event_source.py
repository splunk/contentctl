from __future__ import annotations
from pydantic import BaseModel


class EventSource(BaseModel):
    event_name: str
    fields: list[str]
    field_mappings: list[dict] = None
    convert_to_log_source: list[dict] = None
    example_log: str = None
