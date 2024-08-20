from __future__ import annotations
from pydantic import BaseModel, Field, field_validator, ValidationInfo, model_serializer
from typing import List, Any, Union

from contentctl.objects.story import Story
from contentctl.objects.detection import Detection
from contentctl.objects.enums import SecurityContentProductName
from contentctl.objects.enums import SecurityDomain





class BaselineTags(BaseModel):
    analytic_story: list[Story] = Field(...)
    #deployment: Deployment = Field('SET_IN_GET_DEPLOYMENT_FUNCTION')
    # TODO (#223): can we remove str from the possible types here?
    detections: List[Union[Detection,str]] = Field(...)
    product: List[SecurityContentProductName] = Field(...,min_length=1)
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