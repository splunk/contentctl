from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from contentctl.objects.detection import Detection

from contentctl.objects.security_content_object import SecurityContentObject
from pydantic import field_validator, Field, ValidationInfo


from contentctl.objects.story_tags import StoryTags

#from contentctl.objects.investigation import Investigation

from typing import List

class Story(SecurityContentObject):
    narrative: str = Field(...)
    check_references: bool = False #Validation is done in order, this field must be defined first
    tags: StoryTags = Field(...)

    # enrichments
    #detection_names: List[str] = []
    #investigation_names: List[str] = []
    #baseline_names: List[str] = []
    author_company: str = "no"
    
    #detections: List[Detection] = []
    #investigations: Optional[List[Investigation]] = None
    
    
    @field_validator('narrative')
    @classmethod
    def encode_error(cls, v:str, info:ValidationInfo)->str:
        return super().free_text_field_valid(v,info)

    def getDetections(self, detections:List[Detection])->list[Detection]:
        return [detection for detection in detections if self in detection.tags.analytic_story]

    def getDetectionNames(self, detections:List[Detection])->List[str]:
        return [detection.name for detection in self.getDetections(detections)]
    
    
    # def getInvestigationNames(self)->List[str]:
    #     if self.investigations:
    #         return [investigation.name for investigation in self.investigations]
    #     return []
 