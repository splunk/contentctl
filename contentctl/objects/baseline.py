
from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from contentctl.input.director import DirectorOutputDto

from contentctl.objects.deployment import Deployment

from contentctl.objects.security_content_object import SecurityContentObject
from pydantic import field_validator, ValidationInfo, Field
from typing import Annotated, Optional, List,Any

from contentctl.objects.enums import DataModel, AnalyticsType
from contentctl.objects.baseline_tags import BaselineTags
#from contentctl.objects.deployment import Deployment

# from typing import TYPE_CHECKING
# if TYPE_CHECKING:
#     from contentctl.input.director import DirectorOutputDto


class Baseline(SecurityContentObject):
    # baseline spec
    #name: str
    #id: str
    #version: int
    #date: str
    #author: str
    #contentType: SecurityContentType = SecurityContentType.baselines
    type: Annotated[str,Field(pattern="^Baseline$")] = Field(...)
    datamodel: Optional[List[DataModel]] = None
    #description: str
    search: str = Field(..., min_length=4)
    how_to_implement: str = Field(..., min_length=4)
    known_false_positives: str = Field(..., min_length=4)
    check_references: bool = False #Validation is done in order, this field must be defined first
    tags: BaselineTags = Field(...)

    # enrichment
    deployment: Deployment = Field('SET_IN_GET_DEPLOYMENT_FUNCTION')


    @field_validator('search', 'how_to_implement', 'known_false_positives')
    @classmethod
    def encode_error(cls, v: str, info: ValidationInfo):
        return SecurityContentObject.free_text_field_valid(v,info)


    @field_validator("deployment", mode="before")
    def getDeployment(cls, v:Any, info:ValidationInfo)->Deployment:
        return SecurityContentObject.getDeploymentFromType(info.data.get("type",None), info)