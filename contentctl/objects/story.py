from __future__ import annotations
from typing import TYPE_CHECKING
from contentctl.objects.story_tags import StoryTags
from typing import List, Optional
if TYPE_CHECKING:
    from contentctl.objects.detection import Detection
    from contentctl.objects.investigation import Investigation
    

from contentctl.objects.security_content_object import SecurityContentObject
from pydantic import field_validator, Field, ValidationInfo




#from contentctl.objects.investigation import Investigation



class Story(SecurityContentObject):
    narrative: str = Field(...)
    tags: StoryTags = Field(...)

    # enrichments
    #detection_names: List[str] = []
    #investigation_names: List[str] = []
    #baseline_names: List[str] = []
    author_company: str = "no"
    

    #These enrichments will occur at the very end
    print("enable enrichments for story")
    detections:List[Detection] = []
    investigations: List[Investigation] = []
    
    
    @field_validator('narrative')
    @classmethod
    def encode_error(cls, v:str, info:ValidationInfo)->str:
        return super().free_text_field_valid(v,info)

    # def getDetections(self, detections:List[Detection])->list[Detection]:
    #     return [detection for detection in detections if self in detection.tags.analytic_story]

    # def getDetectionNames(self, detections:List[Detection])->List[str]:
    #     return [detection.name for detection in self.getDetections(detections)]
    def getDetectionNames(self)->List[str]:
        return [detection.name for detection in self.detections]
    
    def getInvestigationNames(self)->List[str]:
        return [investigation.name for investigation in self.investigations]

    
    # def getInvestigationNames(self)->List[str]:
    #     if self.investigations:
    #         return [investigation.name for investigation in self.investigations]
    #     return []
 