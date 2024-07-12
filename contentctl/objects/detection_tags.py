from __future__ import annotations
import uuid
from typing import TYPE_CHECKING, List, Optional, Annotated, Union
from pydantic import BaseModel,Field, NonNegativeInt, PositiveInt, computed_field, UUID4, HttpUrl, ConfigDict, field_validator, ValidationInfo, model_serializer, model_validator
from contentctl.objects.story import Story
if TYPE_CHECKING:
    from contentctl.input.director import DirectorOutputDto



from contentctl.objects.mitre_attack_enrichment import MitreAttackEnrichment
from contentctl.objects.constants import *
from contentctl.objects.observable import Observable
from contentctl.objects.enums import Cis18Value, AssetType, SecurityDomain, RiskSeverity, KillChainPhase, NistCategory, RiskLevel, SecurityContentProductName
from contentctl.objects.atomic import AtomicTest



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
    
    
    mitre_attack_id: List[Annotated[str, Field(pattern="^T[0-9]{4}(.[0-9]{3})?$")]] = []
    nist: list[NistCategory] = []
    observable: List[Observable] = []
    message: Optional[str] = Field(...)
    product: list[SecurityContentProductName] = Field(...,min_length=1)
    required_fields: list[str] = Field(min_length=1)
    
    security_domain: SecurityDomain = Field(...)

    @computed_field
    @property
    def risk_severity(self)->RiskSeverity:
        if self.risk_score >= 80:
            return RiskSeverity('high')
        elif (self.risk_score >= 50 and self.risk_score <= 79):
            return RiskSeverity('medium')
        else:
            return RiskSeverity('low')


    
    cve: List[Annotated[str, "^CVE-[1|2][0-9]{3}-[0-9]+$"]] = []
    atomic_guid: List[AtomicTest] = []
    drilldown_search: Optional[str] = None


    # enrichment
    mitre_attack_enrichments: List[MitreAttackEnrichment] = Field([],validate_default=True)
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
        if self.mitre_attack_enrichments is None:
            return []
        phases:set[KillChainPhase] = set()
        for enrichment in self.mitre_attack_enrichments:
            for tactic in enrichment.mitre_attack_tactics:
                phase = KillChainPhase(ATTACK_TACTICS_KILLCHAIN_MAPPING[tactic])
                phases.add(phase)
        return sorted(list(phases))
    
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
    #annotations: Optional[dict] = None
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

    
    @model_serializer
    def serialize_model(self):
        #Since this field has no parent, there is no need to call super() serialization function
        return {
            "analytic_story": [story.name for story in self.analytic_story],
            "asset_type": self.asset_type.value,
            "cis20": self.cis20,
            "kill_chain_phases": self.kill_chain_phases,
            "nist": self.nist,
            "observable": self.observable,
            "message": self.message,
            "risk_score": self.risk_score,
            "security_domain": self.security_domain,
            "risk_severity": self.risk_severity,
            "mitre_attack_id": self.mitre_attack_id,
            "mitre_attack_enrichments": self.mitre_attack_enrichments
        }
    
        
    @model_validator(mode="after")
    def addAttackEnrichment(self, info:ValidationInfo):
        if len(self.mitre_attack_enrichments) > 0:
            raise ValueError(f"Error, field 'mitre_attack_enrichment' should be empty and dynamically populated at runtime. Instead, this field contained: {self.mitre_attack_enrichments}")
        
        output_dto:Union[DirectorOutputDto,None]= info.context.get("output_dto",None)
        if output_dto is None:
            raise ValueError("Context not provided to detection.detection_tags model post validator")
        
        if output_dto.attack_enrichment.use_enrichment is False:
            return self
        

        mitre_enrichments = []
        missing_tactics = []
        for mitre_attack_id in self.mitre_attack_id:
            try:
                mitre_enrichments.append(output_dto.attack_enrichment.getEnrichmentByMitreID(mitre_attack_id))
            except Exception as e:
                missing_tactics.append(mitre_attack_id)            
        
        if len(missing_tactics) > 0:
            raise ValueError(f"Missing Mitre Attack IDs. {missing_tactics} not found.")
        else:
            self.mitre_attack_enrichments = mitre_enrichments
        
        return self

    '''
    @field_validator('mitre_attack_enrichments', mode="before")
    @classmethod
    def addAttackEnrichments(cls, v:list[MitreAttackEnrichment], info:ValidationInfo)->list[MitreAttackEnrichment]:
        if len(v) > 0:
            raise ValueError(f"Error, field 'mitre_attack_enrichment' should be empty and dynamically populated at runtime. Instead, this field contained: {str(v)}")
        
        
        output_dto:Union[DirectorOutputDto,None]= info.context.get("output_dto",None)
        if output_dto is None:
            raise ValueError("Context not provided to detection.detection_tags.mitre_attack_enrichments")
        
        enrichments = []



        
        return enrichments
    '''

    @field_validator('analytic_story',mode="before")
    @classmethod
    def mapStoryNamesToStoryObjects(cls, v:list[str], info:ValidationInfo)->list[Story]:
        return Story.mapNamesToSecurityContentObjects(v, info.context.get("output_dto",None))
    
    def getAtomicGuidStringArray(self)->List[str]:
        return [str(atomic_guid.auto_generated_guid) for atomic_guid in self.atomic_guid]
            

    @field_validator('atomic_guid',mode="before")
    @classmethod
    def mapAtomicGuidsToAtomicTests(cls, v:List[UUID4], info:ValidationInfo)->List[AtomicTest]:
        if len(v) == 0:
            return []
        
        output_dto:Union[DirectorOutputDto,None]= info.context.get("output_dto",None)
        if output_dto is None:
            raise ValueError("Context not provided to detection.detection_tags.atomic_guid validator")

        
        all_tests:List[AtomicTest]= output_dto.atomic_tests
        
        matched_tests:List[AtomicTest] = []
        missing_tests:List[UUID4] = []
        badly_formatted_guids:List[str] = []
        for atomic_guid_str in v:
            try:
                #Ensure that this is a valid UUID
                atomic_guid = uuid.UUID(str(atomic_guid_str))
            except Exception as e:
                #We will not try to load a test for this since it was invalid
                badly_formatted_guids.append(str(atomic_guid_str))
                continue
            try:
                matched_tests.append(AtomicTest.getAtomicByAtomicGuid(atomic_guid,all_tests))
            except Exception as _:
                missing_tests.append(atomic_guid)

        
        
        
        if len(missing_tests) > 0:
            missing_tests_string = f"\n\tWARNING: Failed to find [{len(missing_tests)}] Atomic Test(s) with the following atomic_guids (called auto_generated_guid in the ART Repo)."\
                                   f"\n\tPlease review the output above for potential exception(s) when parsing the Atomic Red Team Repo."\
                                   f"\n\tVerify that these auto_generated_guid exist and try updating/pulling the repo again.: {[str(guid) for guid in missing_tests]}"
        else:
            missing_tests_string = ""
            

        if len(badly_formatted_guids) > 0:
            if len(badly_formatted_guids) > 0:
                bad_guids_string = f"The following [{len(badly_formatted_guids)}] value(s) are not properly formatted UUIDs: {badly_formatted_guids}\n"
                raise ValueError(f"{bad_guids_string}{missing_tests_string}")
        
        elif len(missing_tests) > 0:
            print(missing_tests_string)

        return matched_tests + [AtomicTest.AtomicTestWhenTestIsMissing(test) for test in missing_tests]
    
