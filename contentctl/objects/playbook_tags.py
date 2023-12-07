from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from contentctl.objects.detection import Detection

from pydantic import BaseModel, validator, ValidationError, Field

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
    platform_tags: list[str] = Field(...,min_length=1)
    playbook_type: PlaybookType = ...
    vpe_type: VpeType = ...
    playbook_fields: list[str] = Field(...)
    product: list[PlaybookProduct] = Field(...,min_length=1)
    use_cases: list[PlaybookUseCases] = Field(...,min_length=0)
    defend_technique_id: DefendTechniques = ...
    
    detection_objects: list[Detection] = []
    