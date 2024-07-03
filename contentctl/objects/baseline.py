
from __future__ import annotations
from typing import TYPE_CHECKING, Annotated, Optional, List,Any
from pydantic import field_validator, ValidationInfo, Field, model_serializer
if TYPE_CHECKING:
    from contentctl.input.director import DirectorOutputDto

from contentctl.objects.deployment import Deployment
from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.enums import DataModel, AnalyticsType
from contentctl.objects.baseline_tags import BaselineTags
from contentctl.objects.enums import DeploymentType
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