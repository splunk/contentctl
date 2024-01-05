from __future__ import annotations
from contentctl.objects.story import Story
    

from typing import Union
from pydantic import BaseModel, Field, field_validator, ValidationInfo
from contentctl.objects.enums import SecurityContentInvestigationProductName, SecurityDomain
from contentctl.objects.security_content_object import SecurityContentObject

class InvestigationTags(BaseModel):
    analytic_story: list[Story] = Field([],min_length=1)
    product: list[SecurityContentInvestigationProductName] = Field(...,min_length=1)
    required_fields: list[str] = Field(min_length=1)
    security_domain: SecurityDomain = Field(...)


    @field_validator('analytic_story',mode="before")
    @classmethod
    def mapStoryNamesToStoryObjects(cls, v:Union[list[str], list[Story]], info:ValidationInfo)->list[Story]:
        return SecurityContentObject.mapNamesToSecurityContentObjects(info.context.get("output_dto",None),info, type(Story))
        