from contentctl.objects.story import Story

from pydantic import BaseModel,Field, NonNegativeInt, PositiveInt, computed_field, UUID4, HttpUrl, ConfigDict, field_validator, ValidationInfo
from contentctl.objects.mitre_attack_enrichment import MitreAttackEnrichment
from contentctl.objects.constants import *
from contentctl.objects.observable import Observable
from contentctl.objects.enums import Cis18Value, AssetType, SecurityDomain, RiskSeverity, KillChainPhase, NistCategory, RiskLevel, SecurityContentProductName
from typing import List, Optional, Annotated, Union
from contentctl.objects.security_content_object import SecurityContentObject



class DetectionTags(BaseModel):
    # detection spec
    model_config = ConfigDict(use_enum_values=True,validate_default=False)
    analytic_story: list[Story] = Field(...)
    asset_type: AssetType = Field(...)
    
    
    confidence: NonNegativeInt = Field(...,le=100)
    impact: NonNegativeInt = Field(...,le=100)
    @computed_field
    @property
    def risk_score(self)->int:
        return round((self.confidence * self.impact)/100)
    
    
    mitre_attack_id: Optional[List[Annotated[str, Field(pattern="^T\d{4}(.\d{3})?$")]]] = None
    nist: Optional[list[NistCategory]] = None
    observable: Optional[list[Observable]] = []
    message: Optional[str] = Field(...)
    product: list[SecurityContentProductName] = Field(...,min_length=1)
    required_fields: list[str] = Field(min_length=1)
    
    security_domain: SecurityDomain = Field(...)
    risk_severity: Optional[RiskSeverity] = None
    cve: Optional[List[Annotated[str, "^CVE-[1|2][0-9]{3}-[0-9]+$"]]] = None
    atomic_guid: Optional[list[UUID4]] = None
    drilldown_search: Optional[str] = None


    # enrichment
    mitre_attack_enrichments: list[MitreAttackEnrichment] = []
    confidence_id: Optional[PositiveInt] = Field(None,ge=1,le=3)
    impact_id: Optional[PositiveInt] = Field(None,ge=1,le=5)
    # context_ids: list = None
    risk_level_id: Optional[NonNegativeInt] = Field(None,le=4)
    risk_level: Optional[RiskLevel] = None
    #observable_str: str = None
    evidence_str: Optional[str] = None

    @computed_field
    @property
    def kill_chain_phases(self)->list[KillChainPhase]:
        from contentctl.helper.constants import ATTACK_TACTICS_KILLCHAIN_MAPPING
        phases:set[str] = set()
        for enrichment in self.mitre_attack_enrichments:
            for tactic in enrichment.mitre_attack_tactics:
                phase = KillChainPhase(ATTACK_TACTICS_KILLCHAIN_MAPPING[tactic])
                phases.add(phase)
        return list(phases)
    
    #enum is intentionally Cis18 even though field is named cis20 for legacy reasons
    @computed_field
    @property
    def cis20(self)->list[Cis18Value]:
        if self.security_domain == SecurityDomain.NETWORK:
            return [Cis18Value.CIS_13]
        else:
            return [Cis18Value.CIS_10]

    
    research_site_url: Optional[HttpUrl] = None
    event_schema: str = "ocsf"
    mappings: Optional[List] = None
    annotations: Optional[dict] = None
    manual_test: Optional[str] = None
    
    
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

    
    @field_validator('analytic_story',mode="before")
    @classmethod
    def mapStoryNamesToStoryObjects(cls, v:Union[list[str], list[Story]], info:ValidationInfo)->list[Story]:
        return SecurityContentObject.mapNamesToSecurityContentObjects(v, info.context.get("output_dto",None), Story)