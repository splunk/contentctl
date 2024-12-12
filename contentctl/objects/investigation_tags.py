from __future__ import annotations
from typing import List
from pydantic import BaseModel, Field, field_validator, ValidationInfo, model_serializer,ConfigDict
from contentctl.objects.story import Story
from contentctl.objects.enums import SecurityContentInvestigationProductName, SecurityDomain

class InvestigationTags(BaseModel):
    model_config = ConfigDict(extra="forbid")
    analytic_story: List[Story] = Field([],min_length=1)
    product: List[SecurityContentInvestigationProductName] = Field(...,min_length=1)
    security_domain: SecurityDomain = Field(...)


    @field_validator('analytic_story',mode="before")
    @classmethod
    def mapStoryNamesToStoryObjects(cls, v:list[str], info:ValidationInfo)->list[Story]:
        return Story.mapNamesToSecurityContentObjects(v, info.context.get("output_dto",None))
    

    @model_serializer
    def serialize_model(self):
        #All fields custom to this model
        model= {
            "analytic_story": [story.name for story in self.analytic_story],
            "product": self.product,
            "security_domain": self.security_domain,
        }
        
        #Combine fields from this model with fields from parent
        
        
        #return the model
        return model