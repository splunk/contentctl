
from pydantic import field_validator, Field, ValidationInfo

from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.story_tags import StoryTags
from contentctl.objects.detection import Detection
from contentctl.objects.investigation import Investigation
from typing import List

class Story(SecurityContentObject):
    narrative: str = Field(...)
    check_references: bool = False #Validation is done in order, this field must be defined first
    tags: StoryTags = Field(...)

    # enrichments
    detection_names: List[str] = []
    investigation_names: List[str] = []
    baseline_names: List[str] = []
    author_company: str = "no"
    
    detections: List[Detection] = []
    investigations: List[Investigation] = []
    
    
    @field_validator('narrative')
    @classmethod
    def encode_error(cls, v:str, info:ValidationInfo):
        return super().free_text_field_valid(v,info)

    def getDetectionNames(self)->List[str]:
        return [detection.name for detection in self.detections]
    def getInvestigationNames(self)->List[str]:
        return [investigation.name for investigation in self.investigations]
 