from __future__ import annotations
from pydantic import BaseModel, Field
from typing import List,Set,Optional, Annotated

from enum import Enum

from contentctl.objects.mitre_attack_enrichment import MitreAttackEnrichment
from contentctl.objects.enums import StoryCategory, DataModel, KillChainPhase, SecurityContentProductName


class StoryUseCase(str,Enum):
   FRAUD_DETECTION = "Fraud Detection"
   COMPLIANCE = "Compliance"
   APPLICATION_SECURITY = "Application Security"
   SECURITY_MONITORING = "Security Monitoring"
   ADVANCED_THREAD_DETECTION = "Advanced Threat Detection"

class StoryTags(BaseModel):
   category: Set[StoryCategory] = Field(...,min_length=1)
   product: Set[SecurityContentProductName] = Field(...,min_length=1)
   usecase: StoryUseCase = Field(...)

   # enrichment
   mitre_attack_enrichments: Optional[List[MitreAttackEnrichment]] = None
   mitre_attack_tactics: Optional[Set[Annotated[str, Field(pattern="^T\d{4}(.\d{3})?$")]]] = None
   datamodels: Optional[Set[DataModel]] = None
   kill_chain_phases: Optional[Set[KillChainPhase]] = None

   def getCategory_conf(self) -> str:
      if len(self.category) > 1:
         print("Story with more than 1 category.  We can only have 1 category, fix it!")
      return self.category.pop()
        
    