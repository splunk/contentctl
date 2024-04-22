from __future__ import annotations
from typing import TYPE_CHECKING
from pydantic import BaseModel, Field, field_validator, ValidationInfo, model_serializer
from typing import List, Any, Union

from contentctl.objects.story import Story
from contentctl.objects.deployment import Deployment
from contentctl.objects.detection import Detection
from contentctl.objects.enums import SecurityContentProductName
from contentctl.objects.enums import SecurityDomain
if TYPE_CHECKING:
    from contentctl.input.director import DirectorOutputDto




class BaselineTags(BaseModel):
    analytic_story: list[Story] = Field(...)
    #deployment: Deployment = Field('SET_IN_GET_DEPLOYMENT_FUNCTION')
    detections: List[Union[Detection,str]] = Field(...)
    product: list[SecurityContentProductName] = Field(...,min_length=1)
    required_fields: List[str] = Field(...,min_length=1)
    security_domain: SecurityDomain = Field(...)


    @field_validator("analytic_story",mode="before")
    def getStories(cls, v:Any, info:ValidationInfo)->List[Story]:
        return Story.mapNamesToSecurityContentObjects(v, info.context.get("output_dto",None))
    
    
    @model_serializer
    def serialize_model(self):    
        #All fields custom to this model
        model= {
            "analytic_story": [story.name for story in self.analytic_story],
            "detections": [detection.name for detection in self.detections if isinstance(detection,Detection)],
            "product": self.product,
            "required_fields":self.required_fields,
            "security_domain":self.security_domain,
            "deployments": None
        }
        
        
        #return the model
        return model
    
    def replaceDetectionNameWithDetectionObject(self, detection:Detection)->bool:
        
        pass

    


    # @field_validator("deployment", mode="before")
    # def getDeployment(cls, v:Any, info:ValidationInfo)->Deployment:         
    #     if v != 'SET_IN_GET_DEPLOYMENT_FUNCTION':
    #         print(f"Deployment defined in YML: {v}")
    #         return v
        
    #     director: Optional[DirectorOutputDto] = info.context.get("output_dto",None)
    #     if not director:
    #         raise ValueError("Cannot set deployment - DirectorOutputDto not passed to Detection Constructor in context")
        
    #     typeField = "Baseline"
    #     deps = [deployment for deployment in director.deployments if deployment.type == typeField]
    #     if len(deps) == 1:
    #         return deps[0]
    #     elif len(deps) == 0:
    #         raise ValueError(f"Failed to find Deployment for type '{typeField}' "\
    #                         f"from  possible {[deployment.type for deployment in director.deployments]}")
    #     else:
    #         raise ValueError(f"Found more than 1 ({len(deps)}) Deployment for type '{typeField}' "\
    #                         f"from  possible {[deployment.type for deployment in director.deployments]}")
        