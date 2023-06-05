import string
import uuid
import requests

from pydantic import BaseModel, validator, ValidationError
from dataclasses import dataclass
from datetime import datetime

from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.enums import DataModel
from contentctl.objects.baseline_tags import BaselineTags
from contentctl.objects.deployment import Deployment
from contentctl.helper.link_validator import LinkValidator
from contentctl.objects.enums import SecurityContentType

class Baseline(SecurityContentObject):
    # baseline spec
    #name: str
    #id: str
    #version: int
    #date: str
    #author: str
    contentType: SecurityContentType = SecurityContentType.baselines
    type: str
    datamodel: list
    #description: str
    search: str
    how_to_implement: str
    known_false_positives: str
    check_references: bool = False #Validation is done in order, this field must be defined first
    references: list
    tags: BaselineTags

    # enrichment
    deployment: Deployment = None




    @validator('type')
    def type_valid(cls, v, values):
        if v != "Baseline":
            raise ValueError('not valid analytics type: ' + values["name"])
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
        
    # @validator('references')
    # def references_check(cls, v, values):
    #     return LinkValidator.SecurityContentObject_validate_references(v, values)
    @validator('search')
    def search_validate(cls, v, values):
        # write search validator
        return v
