import string
import uuid
import requests

from pydantic import BaseModel, field_validator, ValidationError, ValidationInfo, Field, HttpUrl
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Optional, List

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
    #contentType: SecurityContentType = SecurityContentType.baselines
    type: Annotated[str,Field(pattern="^Baseline$")] = ...
    datamodel: list[DataModel] = Field([])
    #description: str
    search: str = ...
    how_to_implement: str = ...
    known_false_positives: str = ...
    check_references: bool = False #Validation is done in order, this field must be defined first
    references: Optional[List[HttpUrl]] = None
    tags: BaselineTags

    # enrichment
    deployment: Optional[Deployment] = None




    

    @field_validator('datamodel')
    def datamodel_valid(cls, v, values):
        for datamodel in v:
            if datamodel not in [el.name for el in DataModel]:
                raise ValueError('not valid data model: ' + values["name"])
        return v

    @field_validator('how_to_implement')
    def encode_error(cls, v:str, info:ValidationInfo):
        return super().free_text_field_valid(v,info)
        
    # @validator('references')
    # def references_check(cls, v, values):
    #     return LinkValidator.SecurityContentObject_validate_references(v, values)
    @field_validator('search')
    def search_validate(cls, v, values):
        # write search validator
        return v
