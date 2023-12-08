import enum
import uuid
import string
import re
import requests

from pydantic import BaseModel, field_validator, ValidationError,computed_field, Field
from dataclasses import dataclass
from datetime import datetime

from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.enums import AnalyticsType
from contentctl.objects.enums import DataModel
from contentctl.objects.enums import SecurityContentType

from contentctl.objects.investigation_tags import InvestigationTags
from contentctl.helper.link_validator import LinkValidator


class Investigation(SecurityContentObject):
    name: str = Field(max_length=75)
    type: str = Field(...,pattern="^Investigation$")
    datamodel: list[DataModel] = ...
    
    search: str = ...
    how_to_implement: str = ...
    known_false_positives: str = ...
    check_references: bool = False #Validation is done in order, this field must be defined first
    inputs: list = None
    tags: InvestigationTags

    # enrichment
    @computed_field
    @property
    def lowercase_name(self)->str:
        return self.name.replace(' ', '_').replace('-','_').replace('.','_').replace('/','_').lower().replace(' ', '_').replace('-','_').replace('.','_').replace('/','_').lower()



    


    @field_validator('how_to_implement', 'known_false_positives')
    @classmethod
    def encode_error(cls, v: str, info: ValidationInfo):
        return SecurityContentObject.free_text_field_valid(v,info)

    