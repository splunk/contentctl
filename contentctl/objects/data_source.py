from __future__ import annotations
from typing import Union, Optional, List, TYPE_CHECKING
from pydantic import model_validator, Field, FilePath, field_validator, ValidationInfo
from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.event_source import EventSource

if TYPE_CHECKING:
    from contentctl.input.director import DirectorOutputDto
    

class DataSource(SecurityContentObject):
    source: str = Field(...)
    sourcetype: str = Field(...)
    separator: Optional[str] = None
    configuration: Optional[str] = None
    supported_TA: Optional[list] = None
    fields: Optional[list] = None
    example_log: Optional[str] = None
    event_sources: list[EventSource] = []


    @field_validator('event_sources',mode="before")
    @classmethod
    def map_event_source_names_to_event_source_objects(cls, v:list[str], info:ValidationInfo)->list[EventSource]:
        director:DirectorOutputDto = info.context.get("output_dto",None)
        return EventSource.mapNamesToSecurityContentObjects(v, director)
