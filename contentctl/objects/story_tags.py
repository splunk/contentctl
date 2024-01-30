from pydantic import BaseModel, Field
from contentctl.objects.mitre_attack_enrichment import MitreAttackEnrichment
from contentctl.objects.enums import StoryCategory, DataModel, KillChainPhase, SecurityContentProductName
from typing import List,Set
from typing_extensions import Annotated
from enum import Enum

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
    mitre_attack_enrichments: List[MitreAttackEnrichment] = Field(...)
    mitre_attack_tactics: Set[Annotated[str, Field(pattern="^T\d{4}(.\d{3})?$")]] = Field(...)
    datamodels: Set[DataModel] = Field(...)
    kill_chain_phases: Set[KillChainPhase] = Field(...)
