import enum
import uuid
import string
import re
import requests

from pydantic import BaseModel, validator, ValidationError
from dataclasses import dataclass
from datetime import datetime

from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.enums import AnalyticsType
from contentctl.objects.enums import DataModel
from contentctl.objects.enums import SecurityContentType
from contentctl.objects.investigation_tags import InvestigationTags
from contentctl.helper.link_validator import LinkValidator


class Investigation(SecurityContentObject):
    # investigation spec
    contentType: SecurityContentType = SecurityContentType.investigations
    #name: str
    #id: str
    #version: int
    #date: str
    #author: str
    type: str
    datamodel: list
    #description: str
    search: str
    how_to_implement: str
    known_false_positives: str
    check_references: bool = False #Validation is done in order, this field must be defined first
    references: list
    inputs: list = None
    tags: InvestigationTags

    # enrichment
    lowercase_name: str = None

    # check_fields=False because we want to override the 
    # name validator in SecurityContentObject 
    # (since we allow longer than the default length)
    @validator('name',check_fields=False)
    def name_max_length(cls, v):
        if len(v) > 75:
            raise ValueError('name is longer then 75 chars: ' + v)
        return v

    @validator('datamodel')
    def datamodel_valid(cls, v, values):
        for datamodel in v:
            if datamodel not in [el.name for el in DataModel]:
                raise ValueError('not valid data model: ' + values["name"])
        return v

    @validator('how_to_implement')
    def encode_error(cls, v, values, field):
        return SecurityContentObject.free_text_field_valid(cls,v,values,field)
    
    @validator('references')
    def references_check(cls, v, values):
        return LinkValidator.SecurityContentObject_validate_references(v, values)
    @validator('search')
    def search_validate(cls, v, values):
        # write search validator
        return v