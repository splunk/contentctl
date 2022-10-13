import re

from pydantic import BaseModel, validator, ValidationError
from bin.objects.mitre_attack_enrichment import MitreAttackEnrichment


class DetectionTags(BaseModel):
    # detection spec
    name: str
    analytic_story: list
    asset_type: str
    confidence: str
    impact: int
    message: str
    mitre_attack_id: list = None
    nist: list = None
    product: list
    atomic_guid : list = None
    risk_score: int
    security_domain: str
    risk_severity: str = None
    cve: list = None
    supported_tas: list = None

    # enrichment
    mitre_attack_enrichments: list[MitreAttackEnrichment] = []
    kill_chain_phases: list = None
    cis20: list = None
    confidence_id: int = None
    impact_id: int = None
    context_ids: list = None
    risk_level_id: int = None
    risk_level: str = None
    observable_str: str = None
    kill_chain_phases_id: list = None


    @validator('cis20')
    def tags_cis20(cls, v, values):
        pattern = 'CIS [0-9]{1,2}'
        for value in v:
            if not re.match(pattern, value):
                raise ValueError('CIS controls are not following the pattern CIS xx: ' + values["name"])
        return v

    @validator('confidence')
    def tags_confidence(cls, v, values):
        v = int(v)
        if not (v > 0 and v <= 100):
             raise ValueError('confidence score is out of range 1-100: ' + values["name"])
        else:
            return v

    @validator('impact')
    def tags_impact(cls, v, values):
        if not (v > 0 and v <= 100):
             raise ValueError('impact score is out of range 1-100: ' + values["name"])
        else:
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
        calculated_risk_score = (int(values['impact']))*(int(values['confidence']))/100
        if calculated_risk_score != int(v):
            raise ValueError('risk_score is calculated wrong: ' + values["name"])
        return v

