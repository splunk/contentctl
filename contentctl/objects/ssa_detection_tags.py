from __future__ import annotations
import re
from typing import List
from pydantic import BaseModel, validator, ValidationError, model_validator, Field

from contentctl.objects.mitre_attack_enrichment import MitreAttackEnrichment
from contentctl.objects.constants import *
from contentctl.objects.enums import SecurityContentProductName

class SSADetectionTags(BaseModel):
    # detection spec
    #name: str
    analytic_story: list
    asset_type: str
    automated_detection_testing: str = None
    cis20: list = None
    confidence: int
    impact: int
    kill_chain_phases: list = None
    message: str
    mitre_attack_id: list = None
    nist: list = None
    observable: list
    product: List[SecurityContentProductName] = Field(...,min_length=1)
    required_fields: list
    risk_score: int
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


    @validator('cis20')
    def tags_cis20(cls, v, values):
        pattern = '^CIS ([0-9]|1[0-9]|20)$' #DO NOT match leading zeroes and ensure no extra characters before or after the string
        for value in v:
            if not re.match(pattern, value):
                raise ValueError(f"CIS control '{value}' is not a valid Control ('CIS 1' -> 'CIS 20'):  {values['name']}")
        return v
    
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
             raise ValueError('confidence score is out of range 1-100.' )
        else:
            return v


    @validator('impact')
    def tags_impact(cls, v, values):
        if not (v > 0 and v <= 100):
             raise ValueError('impact score is out of range 1-100.')
        else:
            return v

    @validator('kill_chain_phases')
    def tags_kill_chain_phases(cls, v, values):
        valid_kill_chain_phases = SES_KILL_CHAIN_MAPPINGS.keys()
        for value in v:
            if value not in valid_kill_chain_phases:
                raise ValueError('kill chain phase not valid. Valid options are ' + str(valid_kill_chain_phases))
        return v

    @validator('mitre_attack_id')
    def tags_mitre_attack_id(cls, v, values):
        pattern = 'T[0-9]{4}'
        for value in v:
            if not re.match(pattern, value):
                raise ValueError('Mitre Attack ID are not following the pattern Txxxx:' )
        return v



    @validator('risk_score')
    def tags_calculate_risk_score(cls, v, values):
        calculated_risk_score = round(values['impact'] * values['confidence'] / 100)
        if calculated_risk_score != int(v):
            raise ValueError(f"Risk Score must be calculated as round(confidence * impact / 100)"
                             f"\n  Expected risk_score={calculated_risk_score}, found risk_score={int(v)}: {values['name']}")
        return v


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