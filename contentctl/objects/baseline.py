
from pydantic import field_validator, ValidationInfo, Field, HttpUrl
from typing import Annotated, Optional, List

from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.enums import DataModel
from contentctl.objects.baseline_tags import BaselineTags
from contentctl.objects.deployment import Deployment
from typing import Any

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from contentctl.input.director import DirectorOutputDto


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
        director: Optional[DirectorOutputDto] = info.context.get("output_dto",None)
        if not director:
            raise ValueError("Cannot set deployment - DirectorOutputDto not passed to Detection Constructor in context")
        
        typeField = info.data.get("type",None)
        deps = [deployment for deployment in director.deployments if deployment.type == typeField]
        if len(deps) == 1:
            return deps[0]
        elif len(deps) == 0:
            raise ValueError(f"Failed to find Deployment for type '{typeField}' "\
                             f"from  possible {[deployment.type for deployment in director.deployments]}")
        else:
            raise ValueError(f"Found more than 1 ({len(deps)}) Deployment for type '{typeField}' "\
                             f"from  possible {[deployment.type for deployment in director.deployments]}")