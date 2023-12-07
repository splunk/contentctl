import re

from pydantic import BaseModel, validator, ValidationError, root_validator,Field, NonNegativeInt, PositiveInt, computed_field, UUID4, HttpUrl
from contentctl.objects.mitre_attack_enrichment import MitreAttackEnrichment
from contentctl.objects.constants import *
from contentctl.objects.observable import Observable
from contentctl.objects.enums import Cis18Value, AssetType, KillChainPhase, NistCategory, RiskLevel
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
    product: list
    required_fields: list
    
    security_domain: str
    risk_severity: str = None
    cve: Optional[List[str]] = Field(pattern="^CVE-[1|2][0-9]{3}-[0-9]+$")
    atomic_guid: Optional[list[UUID4]] = None
    drilldown_search: str = None


    # enrichment
    mitre_attack_enrichments: list[MitreAttackEnrichment] = []
    confidence_id: Optional[PositiveInt] = Field(ge=1,le=3)
    impact_id: Optional[PositiveInt] = Field(ge=1,le=5)
    # context_ids: list = None
    risk_level_id: Optional[NonNegativeInt] = Field(le=4)
    risk_level: Optional[RiskLevel] = None
    #observable_str: str = None
    evidence_str: Optional[str] = None
    kill_chain_phases_id: Optional[dict[KillChainPhase,dict[str,int]]] = None
    
    research_site_url: Optional[HttpUrl] = None
    event_schema: str = "ocsf"
    mappings: list = None
    annotations: dict = None

    
    @validator('nist')
    def tags_nist(cls, v, values):
        # Sourced Courtest of NIST: https://www.nist.gov/system/files/documents/cyberframework/cybersecurity-framework-021214.pdf (Page 19)
        IDENTIFY = [f'ID.{category}' for category in ["AM", "BE", "GV", "RA", "RM"]      ]
        PROTECT  = [f'PR.{category}' for category in ["AC", "AT", "DS", "IP", "MA", "PT"]]
        DETECT   = [f'DE.{category}' for category in ["AE", "CM", "DP"]                  ]
        RESPOND  = [f'RS.{category}' for category in ["RP", "CO", "AN", "MI", "IM"]      ]
        RECOVER  = [f'RC.{category}' for category in ["RP", "IM", "CO"]                  ]
        ALL_NIST_CATEGORIES = IDENTIFY + PROTECT + DETECT + RESPOND + RECOVER

        
        for value in v:
            if not value in ALL_NIST_CATEGORIES:
                raise ValueError(f"NIST Category '{value}' is not a valid category")
        return v

    @validator('confidence')
    def tags_confidence(cls, v, values):
        v = int(v)
        if not (v > 0 and v <= 100):
             raise ValueError('confidence score is out of range 1-100: ' + values["name"])
        else:
            return v

    # @validator('context_ids')
    # def tags_context(cls, v, values):
    #     context_list = SES_CONTEXT_MAPPING.keys()
    #     for value in v:
    #         if value not in context_list:
    #             raise ValueError('context value not valid for ' + values["name"] + '. valid options are ' + str(context_list) )
    #     return v

    @validator('impact')
    def tags_impact(cls, v, values):
        if not (v > 0 and v <= 100):
             raise ValueError('impact score is out of range 1-100: ' + values["name"])
        else:
            return v

    @validator('kill_chain_phases')
    def tags_kill_chain_phases(cls, v, values):
        valid_kill_chain_phases = SES_KILL_CHAIN_MAPPINGS.keys()
        for value in v:
            if value not in valid_kill_chain_phases:
                raise ValueError('kill chain phase not valid for ' + values["name"] + '. valid options are ' + str(valid_kill_chain_phases))
        return v

    @validator('mitre_attack_id')
    def tags_mitre_attack_id(cls, v, values):
        pattern = 'T[0-9]{4}'
        for value in v:
            if not re.match(pattern, value):
                raise ValueError('Mitre Attack ID are not following the pattern Txxxx: ' + values["name"])
        return v

    @validator('product')
    def tags_product(cls, v, values):
        valid_products = [
            "Splunk Enterprise", "Splunk Enterprise Security", "Splunk Cloud",
            "Splunk Security Analytics for AWS", "Splunk Behavioral Analytics"
        ]

        for value in v:
            if value not in valid_products:
                raise ValueError('product is not valid for ' + values['name'] + '. valid products are ' + str(valid_products))
        return v

    @validator('risk_score')
    def tags_calculate_risk_score(cls, v, values):
        calculated_risk_score = round(values['impact'] * values['confidence'] / 100)
        if calculated_risk_score != int(v):
            raise ValueError(f"Risk Score must be calculated as round(confidence * impact / 100)"
                             f"\n  Expected risk_score={calculated_risk_score}, found risk_score={int(v)}: {values['name']}")
        return v
    
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

    