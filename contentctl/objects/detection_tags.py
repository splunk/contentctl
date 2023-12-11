import re

from pydantic import BaseModel, field_validator, ValidationError, root_validator,Field, NonNegativeInt, PositiveInt, computed_field, UUID4, HttpUrl
from contentctl.objects.mitre_attack_enrichment import MitreAttackEnrichment
from contentctl.objects.constants import *
from contentctl.objects.observable import Observable
from contentctl.objects.enums import Cis18Value, AssetType, KillChainPhase, NistCategory, RiskLevel, SecurityContentProductName
from typing import List, Optional, Annotated

class DetectionTags(BaseModel):
    # detection spec
    name: str
    analytic_story: list
    asset_type: AssetType = ...
    #enum is intentionally Cis18 even though field is named cis20 for legacy reasons
    cis20: Optional[List[Cis18Value]] = None 
    confidence: NonNegativeInt = Field(...,le=100)
    impact: NonNegativeInt = Field(...,le=100)
    @computed_field
    @property
    def risk_score(self)->int:
        return round((self.confidence * self.impact)/100)
    
    kill_chain_phases: Optional[list[KillChainPhase]] = None
    mitre_attack_id: Optional[List[Annotated[str, Field(pattern="^T\d{4}(.\d{3})?$")]]] = None
    nist: Optional[list[NistCategory]] = None
    observable: list[Observable] = []
    message: Optional[str] = ...
    product: list[SecurityContentProductName] = Field(...,min_length=1)
    required_fields: list
    
    security_domain: str
    risk_severity: str = None
    cve: Optional[List[str]] = Field(None,pattern="^CVE-[1|2][0-9]{3}-[0-9]+$")
    atomic_guid: Optional[list[UUID4]] = None
    drilldown_search: str = None


    # enrichment
    mitre_attack_enrichments: list[MitreAttackEnrichment] = []
    confidence_id: Optional[PositiveInt] = Field(None,ge=1,le=3)
    impact_id: Optional[PositiveInt] = Field(None,ge=1,le=5)
    # context_ids: list = None
    risk_level_id: Optional[NonNegativeInt] = Field(None,le=4)
    risk_level: Optional[RiskLevel] = None
    #observable_str: str = None
    evidence_str: Optional[str] = None
    kill_chain_phases_id: Optional[dict[KillChainPhase,dict[str,int]]] = None
    
    research_site_url: Optional[HttpUrl] = None
    event_schema: str = "ocsf"
    mappings: list = None
    annotations: dict = None

    
    
    # The following validator is temporarily disabled pending further discussions
    # @validator('message')
    # def validate_message(cls,v,values):
        
    #     observables:list[Observable] = values.get("observable",[])
    #     observable_names = set([o.name for o in observables])
    #     #find all of the observables used in the message by name
    #     name_match_regex = r"\$([^\s.]*)\$"
        
    #     message_observables = set()

    #     #Make sure that all observable names in 
    #     for match in re.findall(name_match_regex, v):
    #         #Remove
    #         match_without_dollars = match.replace("$", "")
    #         message_observables.add(match_without_dollars)
        

    #     missing_observables = message_observables - observable_names
    #     unused_observables = observable_names - message_observables
    #     if len(missing_observables) > 0:
    #         raise ValueError(f"The following observables are referenced in the message, but were not declared as observables: {missing_observables}")
        
    #     if len(unused_observables) > 0:
    #         raise ValueError(f"The following observables were declared, but are not referenced in the message: {unused_observables}")        
    #     return v

    