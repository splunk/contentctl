from __future__ import annotations
from pydantic import BaseModel


class DataSource(BaseModel):
    name: str
    id: str
    author: str
    source: str
    sourcetype: str
    separator: str = None
    configuration: str = None
    supported_TA: dict
    event_names: list = None
    fields: list = None
    example_log: str = None