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
    event_sources: list = None
    fields: list = None
    example_log: str = None

    def model_post_init(self, ctx:dict[str,Any]):
        context = ctx.get("output_dto")
        
        if self.event_names:
            self.event_sources = []
            for event_source in context.event_sources:
                if any(event['event_name'] == event_source.event_name for event in self.event_names):
                    self.event_sources.append(event_source)

        return self