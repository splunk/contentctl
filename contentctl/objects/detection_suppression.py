import re

from pydantic import BaseModel, validator, ValidationError, root_validator
from contentctl.objects.mitre_attack_enrichment import MitreAttackEnrichment
from contentctl.objects.constants import *

class DetectionSuppression(BaseModel):
    enabled: bool = False
    fields: list[str] = []
    window: str = '86400s'
