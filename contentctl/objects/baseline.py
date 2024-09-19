
from __future__ import annotations
from typing import Annotated, Optional, List,Any
from pydantic import field_validator, ValidationInfo, Field, model_serializer
from contentctl.objects.deployment import Deployment
from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.enums import DataModel
from contentctl.objects.baseline_tags import BaselineTags

from contentctl.objects.constants import CONTENTCTL_MAX_SEARCH_NAME_LENGTH

class Baseline(SecurityContentObject):
    name:str = Field(...,max_length=CONTENTCTL_MAX_SEARCH_NAME_LENGTH)
    type: Annotated[str,Field(pattern="^Baseline$")] = Field(...)
    datamodel: Optional[List[DataModel]] = None
    search: str = Field(..., min_length=4)
    how_to_implement: str = Field(..., min_length=4)
    known_false_positives: str = Field(..., min_length=4)
    tags: BaselineTags = Field(...)

    # enrichment
    deployment: Deployment = Field({})
    

    @field_validator("deployment", mode="before")
    def getDeployment(cls, v:Any, info:ValidationInfo)->Deployment:
        return Deployment.getDeployment(v,info)
    

    @model_serializer
    def serialize_model(self):
        #Call serializer for parent
        super_fields = super().serialize_model()
        
        #All fields custom to this model
        model= {
            "tags": self.tags.model_dump(),
            "type": self.type,
            "search": self.search,
            "how_to_implement":self.how_to_implement,
            "known_false_positives":self.known_false_positives,
            "datamodel": self.datamodel,
        }
        
        #Combine fields from this model with fields from parent
        super_fields.update(model)
        
        #return the model
        return super_fields