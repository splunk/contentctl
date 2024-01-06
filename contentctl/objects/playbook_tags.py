from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from contentctl.objects.detection import Detection

from pydantic import BaseModel, Field
from typing import Optional

import enum


class PlaybookProduct(str,enum.Enum):
    SPLUNK_SOAR = "Splunk SOAR"

class PlaybookUseCase(str,enum.Enum):
    PHISHING = "Phishing"
    ENDPOINT = "Endpoint"
    ENRICHMENT = "Enrichment"
    
class PlaybookType(str,enum.Enum):
    INPUT = "Input"
    AUTOMATION = "Automation"

class VpeType(str,enum.Enum):
    MODERN = "Modern"
    CLASSIC = "Classic"
class DefendTechnique(str,enum.Enum):
    D3_AL = "D3-AL"
    D3_DNSDL = "D3-DNSDL"
    D3_DA = "D3-DA"
    D3_IAA = "D3-IAA"
    D3_IRA = "D3-IRA"
    D3_OTF = "D3-OTF"
class PlaybookTag(BaseModel):
    analytic_story: list = None
    detections: list = None
    platform_tags: list[str] = Field(...,min_length=0)
    playbook_type: PlaybookType = ...
    vpe_type: VpeType = ...
    playbook_fields: list[str] = Field([], min_length=0)
    product: list[PlaybookProduct] = Field([],min_length=0)
    use_cases: list[PlaybookUseCase] = Field([],min_length=0)
    defend_technique_id: Optional[DefendTechnique] = None
    
    detection_objects: list[Detection] = []
    