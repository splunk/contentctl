from __future__ import annotations
from pydantic import BaseModel, Field, model_serializer, ConfigDict
from typing import List,Set,Optional, Annotated

from enum import Enum

from contentctl.objects.mitre_attack_enrichment import MitreAttackEnrichment
from contentctl.objects.enums import StoryCategory, DataModel, KillChainPhase, SecurityContentProductName
from contentctl.objects.annotated_types import CVE_TYPE,MITRE_ATTACK_ID_TYPE

class StoryUseCase(str,Enum):
   FRAUD_DETECTION = "Fraud Detection"
   COMPLIANCE = "Compliance"
   APPLICATION_SECURITY = "Application Security"
   SECURITY_MONITORING = "Security Monitoring"
   ADVANCED_THREAD_DETECTION = "Advanced Threat Detection"
   INSIDER_THREAT = "Insider Threat"
   OTHER = "Other"


class StoryTags(BaseModel):
   model_config = ConfigDict(extra='forbid')
   category: List[StoryCategory] = Field(...,min_length=1)
   product: List[SecurityContentProductName] = Field(...,min_length=1)
   usecase: StoryUseCase = Field(...)

   # enrichment
   mitre_attack_enrichments: Optional[List[MitreAttackEnrichment]] = None
   mitre_attack_tactics: Optional[Set[MITRE_ATTACK_ID_TYPE]] = None
   datamodels: Optional[Set[DataModel]] = None
   kill_chain_phases: Optional[Set[KillChainPhase]] = None
   cve: List[CVE_TYPE] = []
   group: List[str] = Field([], description="A list of groups who leverage the techniques list in this Analytic Story.")

   def getCategory_conf(self) -> str:
      #if len(self.category) > 1:
      #   print("Story with more than 1 category.  We can only have 1 category, fix it!")
      return list(self.category)[0]
   
   @model_serializer
   def serialize_model(self):
      #no super to call
      return {
         "category": list(self.category),
         "product": list(self.product),
         "usecase": self.usecase,
         "mitre_attack_enrichments": self.mitre_attack_enrichments,
         "mitre_attack_tactics": list(self.mitre_attack_tactics) if self.mitre_attack_tactics is not None else None,
         "datamodels": list(self.datamodels) if self.datamodels is not None else None,
         "kill_chain_phases": list(self.kill_chain_phases) if self.kill_chain_phases is not None else None  
      }

        
    