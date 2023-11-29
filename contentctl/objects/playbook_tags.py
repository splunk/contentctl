
from pydantic import BaseModel, validator, ValidationError, Field
from contentctl.objects.detection import Detection
from contentctl.objects.detection import Detection
import enum


class PlaybookProduct(str,enum.Enum):
    SPLUNK_SOAR = "Splunk SOAR"

class PlaybookUseCases(str,enum.Enum):
    PHISHING = "Phishing"
    ENDPOINT = "Endpoint"

class PlaybookType(str,enum.Enum):
    INPUT = "Input"

class VpeType(str,enum.Enum):
    MODERN = "Modern"

class DefendTechniques(str,enum.Enum):
    D3_AL = "D3-AL"


class PlaybookTag(BaseModel):
    #analytic_story: list = None
    #detections: list = None
    platform_tags: list[str] = Field(...,gt=0)
    playbook_type: PlaybookType = ...
    vpe_type: VpeType = ...
    playbook_fields: list[str] = Field(...)
    product: list[PlaybookProduct] = Field(...,gt=0)
    use_cases: list[PlaybookUseCases] = Field(...,gt=0)
    defend_technique_id: DefendTechniques = ...
    
    detection_objects: list[Detection] = []
    