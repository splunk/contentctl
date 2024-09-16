from __future__ import annotations
from typing import TYPE_CHECKING,List,Any
from contentctl.objects.story_tags import StoryTags
from pydantic import Field, model_serializer,computed_field
import re
if TYPE_CHECKING:
    from contentctl.objects.detection import Detection
    from contentctl.objects.investigation import Investigation
    from contentctl.objects.baseline import Baseline
    from contentctl.objects.data_source import DataSource

from contentctl.objects.security_content_object import SecurityContentObject





#from contentctl.objects.investigation import Investigation



class Story(SecurityContentObject):
    narrative: str = Field(...)
    tags: StoryTags = Field(...)

    # enrichments
    #detection_names: List[str] = []
    #investigation_names: List[str] = []
    #baseline_names: List[str] = []

    # These are updated when detection and investigation objects are created.
    # Specifically in the model_post_init functions
    detections:List[Detection] = []
    investigations: List[Investigation] = []
    baselines: List[Baseline] = []
    
    
    @computed_field
    @property
    def data_sources(self)-> list[DataSource]:
        # Only add a data_source if it does not already exist in the story
        data_source_objects:set[DataSource] = set()
        for detection in self.detections:
            data_source_objects.update(set(detection.data_source_objects))
        
        return sorted(list(data_source_objects))


    def storyAndInvestigationNamesWithApp(self, app_name:str)->List[str]:
        return [f"{app_name} - {name} - Rule" for name in self.detection_names] + \
               [f"{app_name} - {name} - Response Task" for name in self.investigation_names]
        
    @model_serializer
    def serialize_model(self):
        #Call serializer for parent
        super_fields = super().serialize_model()
        
        #All fields custom to this model
        model= {
            "narrative": self.narrative,
            "tags": self.tags.model_dump(),
            "detection_names": self.detection_names,
            "investigation_names": self.investigation_names,
            "baseline_names": self.baseline_names,
            "author_company": self.author_company,
            "author_name":self.author_name
        }
        detections:list[dict[str,Any]] = []
        for detection in self.detections:
            new_detection:dict[str,Any] = {
                "name":detection.name,
                "source":detection.source,
                "type":detection.type
            }
            
            new_detection['tags'] = {"mitre_attack_enrichments": [{"mitre_attack_technique":  enrichment.mitre_attack_technique} for enrichment in detection.tags.mitre_attack_enrichments]}
            
            detections.append(new_detection)

        model['detections'] = detections
        #Combine fields from this model with fields from parent
        super_fields.update(model)
        
        #return the model
        return super_fields

    @computed_field
    @property
    def author_name(self)->str:
        match_author = re.search(r'^([^,]+)', self.author)
        if match_author is None:
            return 'no'
        else:
            return match_author.group(1)

    @computed_field
    @property
    def author_company(self)->str:
        match_company = re.search(r',\s?(.*)$', self.author)
        if match_company is None:
            return 'no'
        else:
            return match_company.group(1)

    @computed_field
    @property
    def author_email(self)->str:
        return "-"

    @computed_field
    @property
    def detection_names(self)->List[str]:
        return [detection.name for detection in self.detections]
    
    @computed_field
    @property
    def investigation_names(self)->List[str]:
        return [investigation.name for investigation in self.investigations]

    @computed_field
    @property
    def baseline_names(self)->List[str]:        
        return [baseline.name for baseline in self.baselines]
    
