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
    event_names: Optional[list] = None
    fields: Optional[list] = None
    example_log: Optional[str] = None

    event_sources: Optional[list[EventSource]] = None


    def model_post_init(self, ctx:dict[str,Any]):
        context = ctx.get("output_dto")
        
        if self.event_names:
            self.event_sources = []
            for event_source in context.event_sources:
                if any(event['event_name'] == event_source.name for event in self.event_names):
                    self.event_sources.append(event_source)

        return self