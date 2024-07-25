from __future__ import annotations
from typing import Optional, Any
from pydantic import Field, FilePath, model_serializer
from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.event_source import EventSource

class DataSource(SecurityContentObject):
    source: str = Field(...)
    sourcetype: str = Field(...)
    separator: Optional[str] = None
    configuration: Optional[str] = None
    supported_TA: Optional[list] = None
    fields: Optional[list] = None
    field_mappings: Optional[list] = None
    convert_to_log_source: Optional[list] = None
    example_log: Optional[str] = None


    @model_serializer
    def serialize_model(self):
        #Call serializer for parent
        super_fields = super().serialize_model()
        
        #All fields custom to this model
        model:dict[str,Any] = {
            "source": self.source,
            "sourcetype": self.sourcetype,
            "separator": self.separator,
            "configuration": self.configuration,
            "supported_TA": self.supported_TA,
            "fields": self.fields,
            "field_mappings": self.field_mappings,
            "convert_to_log_source": self.convert_to_log_source,
            "example_log":self.example_log
        }
        
        
        #Combine fields from this model with fields from parent
        super_fields.update(model)
        
        #return the model
        return super_fields