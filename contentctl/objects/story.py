from __future__ import annotations
from typing import TYPE_CHECKING,List
from contentctl.objects.story_tags import StoryTags
from pydantic import field_validator, Field, ValidationInfo
if TYPE_CHECKING:
    from contentctl.objects.detection import Detection
    from contentctl.objects.investigation import Investigation
    

from contentctl.objects.security_content_object import SecurityContentObject





#from contentctl.objects.investigation import Investigation



class Story(SecurityContentObject):
    narrative: str = Field(...)
    tags: StoryTags = Field(...)

    # enrichments
    #detection_names: List[str] = []
    #investigation_names: List[str] = []
    #baseline_names: List[str] = []
    author_company: str = "no"
    

    # These are updated when detection and investigation objects are created.
    # Specifically in the model_post_init functions
    detections:List[Detection] = []
    investigations: List[Investigation] = []
    
    
    @field_validator('narrative')
    @classmethod
    def encode_error(cls, v:str, info:ValidationInfo)->str:
        return super().free_text_field_valid(v,info)

    def getDetectionNames(self)->List[str]:
        return [detection.name for detection in self.detections]
    
    def getInvestigationNames(self)->List[str]:
        return [investigation.name for investigation in self.investigations]

    
    
 