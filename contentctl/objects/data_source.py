from __future__ import annotations
from typing import Union, Optional, List
from pydantic import model_validator, Field, FilePath
from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.event_source import EventSource

class DataSource(SecurityContentObject):
    source: str = Field(...)
    sourcetype: str = Field(...)
    separator: Optional[str] = None
    configuration: Optional[str] = None
    supported_TA: Optional[list] = None
    fields: Optional[list] = None
    example_log: Optional[str] = None

    event_sources: Optional[list] = None

