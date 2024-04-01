from __future__ import annotations
from typing import TYPE_CHECKING, Optional, List
from pydantic import BaseModel, Field
import enum
from contentctl.objects.detection import Detection


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
    D3_ER = "D3-ER"
    D3_RE = "D3-RE"
    D3_URA = "D3-URA"
    D3_DNRA = "D3-DNRA"
    D3_IPRA = "D3-IPRA"
    D3_FHRA = "D3-FHRA"
    D3_SRA = "D3-SRA"
    D3_RUAA = "D3-RUAA"
class PlaybookTag(BaseModel):
    analytic_story: Optional[list] = None
    detections: Optional[list] = None
    platform_tags: list[str] = Field(...,min_length=0)
    playbook_type: PlaybookType = Field(...)
    vpe_type: VpeType = Field(...)
    playbook_fields: list[str] = Field([], min_length=0)
    product: list[PlaybookProduct] = Field([],min_length=0)
    use_cases: list[PlaybookUseCase] = Field([],min_length=0)
    defend_technique_id: Optional[List[DefendTechnique]] = None
    
    detection_objects: list[Detection] = []
    