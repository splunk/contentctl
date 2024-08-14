from __future__ import annotations
from typing import List
from pydantic import BaseModel, computed_field, constr, field_validator, model_validator, Field

from contentctl.objects.mitre_attack_enrichment import MitreAttackEnrichment
from contentctl.objects.constants import *
from contentctl.objects.enums import SecurityContentProductName

class SSADetectionTags(BaseModel):
    # detection spec
    #name: str
    analytic_story: list
    asset_type: str
    automated_detection_testing: str = None
    cis20: list[constr(pattern=r"^CIS (\d|1\d|20)$")] = None #DO NOT match leading zeroes and ensure no extra characters before or after the string
    confidence: int = Field(..., ge=1, le=100)
    impact: int = Field(..., ge=1, le=100)
    kill_chain_phases: list = None
    message: str
    mitre_attack_id: list[constr(pattern=r"^T[0-9]{4}$")] = None
    nist: list = None
    observable: list
    product: List[SecurityContentProductName] = Field(...,min_length=1)
    required_fields: list
    @computed_field
    def risk_score(self) -> int:
        return round((self.confidence * self.impact)/100)
    security_domain: str
    risk_severity: str = None
    cve: list = None
    supported_tas: list = None
    atomic_guid: list = None
    drilldown_search: str = None
    manual_test: str = None


    # enrichment
    mitre_attack_enrichments: list[MitreAttackEnrichment] = []
    confidence_id: int = None
    impact_id: int = None
    context_ids: list = None
    risk_level_id: int = None
    risk_level: str = None
    observable_str: str = None
    evidence_str: str = None
    analytics_story_str: str = None
    kill_chain_phases_id:dict = None
    kill_chain_phases_str:str = None
    research_site_url: str = None
    event_schema: str = None
    mappings: list = None
    annotations: dict = None


    
    @field_validator('nist', mode='before')
    def tags_nist(cls, nist):
        # Sourced Courtest of NIST: https://www.nist.gov/system/files/documents/cyberframework/cybersecurity-framework-021214.pdf (Page 19)
        IDENTIFY = [f'ID.{category}' for category in ["AM", "BE", "GV", "RA", "RM"]      ]
        PROTECT  = [f'PR.{category}' for category in ["AC", "AT", "DS", "IP", "MA", "PT"]]
        DETECT   = [f'DE.{category}' for category in ["AE", "CM", "DP"]                  ]
        RESPOND  = [f'RS.{category}' for category in ["RP", "CO", "AN", "MI", "IM"]      ]
        RECOVER  = [f'RC.{category}' for category in ["RP", "IM", "CO"]                  ]
        ALL_NIST_CATEGORIES = IDENTIFY + PROTECT + DETECT + RESPOND + RECOVER

        
        for value in nist:
            if value not in ALL_NIST_CATEGORIES:
                raise ValueError(f"NIST Category '{value}' is not a valid category")
        return nist

    @field_validator('kill_chain_phases')
    def tags_kill_chain_phases(cls, kill_chain_phases):
        valid_kill_chain_phases = SES_KILL_CHAIN_MAPPINGS.keys()
        for value in kill_chain_phases:
            if value not in valid_kill_chain_phases:
                raise ValueError('kill chain phase not valid. Valid options are ' + str(valid_kill_chain_phases))
        return kill_chain_phases

    @model_validator(mode="after")
    def tags_observable(self):
        valid_roles = SES_OBSERVABLE_ROLE_MAPPING.keys()
        valid_types = SES_OBSERVABLE_TYPE_MAPPING.keys()
        
        for value in self.observable:
            if value['type'] in valid_types:
                if 'Splunk Behavioral Analytics' in self.product:
                    continue

                if 'role' not in value:
                    raise ValueError('Observable role is missing')
                for role in value['role']:
                    if role not in valid_roles:
                        raise ValueError(f'Observable role ' + role + ' not valid. Valid options are {str(valid_roles)}')
            else:
                raise ValueError(f'Observable type ' + value['type'] + ' not valid. Valid options are {str(valid_types)}')
        return self