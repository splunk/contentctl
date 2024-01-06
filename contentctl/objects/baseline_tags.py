from __future__ import annotations
from typing import TYPE_CHECKING
from contentctl.objects.story import Story
from contentctl.objects.deployment import Deployment
from contentctl.objects.detection import Detection
from contentctl.objects.enums import SecurityContentProductName
from contentctl.objects.enums import SecurityDomain
if TYPE_CHECKING:
    from contentctl.input.director import DirectorOutputDto

from pydantic import BaseModel, Field, field_validator, ValidationInfo
from typing import List, Optional, Any




class BaselineTags(BaseModel):
    analytic_story: list[Story] = Field(...)
    deployment: Deployment = Field('SET_IN_GET_DEPLOYMENT_FUNCTION')
    detections: List[Detection] = Field(...)
    product: list[SecurityContentProductName] = Field(...,min_length=1)
    required_fields: List[str] = Field(...,min_length=1)
    security_domain: SecurityDomain = Field(...)

    @field_validator("deployment", mode="before")
    def getDeployment(cls, v:Any, info:ValidationInfo)->Deployment:         
        if v != 'SET_IN_GET_DEPLOYMENT_FUNCTION':
            print(f"Deployment defined in YML: {v}")
            return v
        
        director: Optional[DirectorOutputDto] = info.context.get("output_dto",None)
        if not director:
            raise ValueError("Cannot set deployment - DirectorOutputDto not passed to Detection Constructor in context")
        
        typeField = "Baseline"
        deps = [deployment for deployment in director.deployments if deployment.type == typeField]
        if len(deps) == 1:
            return deps[0]
        elif len(deps) == 0:
            raise ValueError(f"Failed to find Deployment for type '{typeField}' "\
                            f"from  possible {[deployment.type for deployment in director.deployments]}")
        else:
            raise ValueError(f"Found more than 1 ({len(deps)}) Deployment for type '{typeField}' "\
                            f"from  possible {[deployment.type for deployment in director.deployments]}")
        