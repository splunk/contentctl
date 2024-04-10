from __future__ import annotations
from typing import TYPE_CHECKING,Union, Optional, List, Any
import os.path
import re
import pathlib
from pydantic import BaseModel, field_validator, model_validator, ValidationInfo, Field, computed_field, model_serializer

from contentctl.objects.macro import Macro
from contentctl.objects.lookup import Lookup
if TYPE_CHECKING:
    from contentctl.input.director import DirectorOutputDto
    
from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.enums import AnalyticsType
from contentctl.objects.enums import DataModel
from contentctl.objects.enums import DetectionStatus
from contentctl.objects.enums import NistCategory

from contentctl.objects.detection_tags import DetectionTags
from contentctl.objects.deployment import Deployment
from contentctl.objects.unit_test import UnitTest

#from contentctl.objects.baseline import Baseline
#from contentctl.objects.playbook import Playbook
from contentctl.objects.enums import DataSource,ProvidingTechnology



class Detection_Abstract(SecurityContentObject):
    #contentType: SecurityContentType = SecurityContentType.detections
    type: AnalyticsType = Field(...)
    status: DetectionStatus = Field(...)
    data_source: Optional[List[str]] = None
    tags: DetectionTags = Field(...)
    search: Union[str, dict] = Field(...)
    how_to_implement: str = Field(..., min_length=4)
    known_false_positives: str = Field(..., min_length=4)
    check_references: bool = False  
    #data_source: Optional[List[DataSource]] = None

    
    tests: list[UnitTest] = []

    @computed_field
    @property
    def datamodel(self)->List[DataModel]:
        if isinstance(self.search, str):
            return [dm for dm in DataModel if dm.value in self.search]
        else:
            return []
    
    @computed_field
    @property
    def source(self)->str:
        if self.file_path is not None:
            return self.file_path.absolute().parent.name
        else:
            raise ValueError(f"Cannot get 'source' for detection {self.name} - 'file_path' was None.")

    deployment: Deployment = Field('SET_IN_GET_DEPLOYMENT_FUNCTION')
    annotations: dict[str,Union[List[Any],int]] = {}
    #playbooks: list[Playbook] = []
    #baselines: list[Baseline] = []
    
    @computed_field
    @property
    def mappings(self)->dict[str, List[str]]:
        mappings = {}
        if self.tags.mitre_attack_id is not None and len(self.tags.mitre_attack_id) > 0:
            mappings['mitre_attack'] = self.tags.mitre_attack_id
        if len(self.tags.kill_chain_phases) > 0:
            mappings['kill_chain_phases'] = self.tags.kill_chain_phases
        if self.tags.nist is not None and len(self.tags.nist) > 0:
             mappings['nist'] = self.tags.nist
        if len(self.tags.cis20) > 0:
            mappings["cis20"] = self.tags.cis20
        return mappings

    macros: list[Macro] = Field([],validate_default=True)
    lookups: list[Lookup] = []
    cve_enrichment: Optional[List[dict]] = None
    splunk_app_enrichment: Optional[List[dict]] = None
    
    @computed_field
    @property
    def nes_fields(self)->Optional[str]:
        if self.deployment.alert_action.notable is not None:
            print(','.join(self.deployment.alert_action.notable.nes_fields)  )
            return ','.join(self.deployment.alert_action.notable.nes_fields)
        else:
            return None
    
    providing_technologies: Optional[List[ProvidingTechnology]] = None
    risk: Optional[list[dict]] = None
    
    class Config:
        use_enum_values = True


    @model_serializer
    def serialize_model(self):
        #Call serializer for parent
        super_fields = super().serialize_model()
        
        #All fields custom to this model
        model= {
            "tags": self.tags.model_dump(),
            "search": self.search,
            "how_to_implement":self.how_to_implement,
            "known_false_positives":self.known_false_positives,
            "datamodel": self.datamodel,
            "macros": self.macros,
            "lookups": self.lookups,
            "source": self.source,
            "nes_fields": self.nes_fields,
        }
        
        #Combine fields from this model with fields from parent
        model.update(super_fields)
        
        #return the model
        return model


    def model_post_init(self, ctx:dict[str,Any]):
        # director: Optional[DirectorOutputDto] = ctx.get("output_dto",None)
        # if not isinstance(director,DirectorOutputDto):
        #     raise ValueError("DirectorOutputDto was not passed in context of Detection model_post_init")
        director: Optional[DirectorOutputDto] = ctx.get("output_dto",None)
        for story in self.tags.analytic_story:
            story.detections.append(self)

    
    @field_validator('lookups',mode="before")
    @classmethod
    def getDetectionLookups(cls, v:list[str], info:ValidationInfo)->list[Lookup]:
        return Lookup.mapNamesToSecurityContentObjects(v, info.context.get("output_dto",None))

    @field_validator('macros',mode="before")
    @classmethod
    def getDetectionMacros(cls, v:list[str], info:ValidationInfo)->list[Macro]:
        director:DirectorOutputDto = info.context.get("output_dto",None)
        
        search:Union[str,dict] = info.data.get("search",None)
        if not isinstance(search,str):
            #The search was sigma formatted (or failed other validation and was None), so we will not validate macros in it
            return []
        
        search_name:Union[str,Any] = info.data.get("name",None)
        assert isinstance(search_name,str), f"Expected 'search_name' to be a string, instead it was [{type(search_name)}]"
        
        
        
        filter_macro_name = search_name.replace(' ', '_').replace('-', '_').replace('.', '_').replace('/', '_').lower() + '_filter'
        try:        
            filter_macro = Macro.mapNamesToSecurityContentObjects([filter_macro_name], director)[0]
        except:
            # Filter macro did not exist, so create one at runtime
            filter_macro = Macro.model_validate({"name":filter_macro_name, 
                                                "definition":'search *', 
                                                "description":'Update this macro to limit the output results to filter out false positives.'})
            director.macros.append(filter_macro)
        
        macros_from_search = Macro.get_macros(search, director)
        
        return  macros_from_search + [filter_macro]
        

        
        
    def getAnnotationsDictForJson(self)->dict[str,Union[List[Any],int]]:
        result_dict:dict[str,Union[List[Any],int]] = {}
        for k in self.annotations:
            ls = self.annotations.get(k,[])
            if isinstance(ls, List) and True in [True for obj in ls if isinstance(obj, SecurityContentObject)]:
                result_dict[k] = [obj.name for obj in ls]
            else:
                result_dict[k] = ls
        return result_dict

    def get_content_dependencies(self)->list[SecurityContentObject]:
        #Do this separately to satisfy type checker
        objects: list[SecurityContentObject] = []
        objects += self.macros 
        objects += self.lookups     
        return objects
    
    
    @field_validator("deployment", mode="before")
    def getDeployment(cls, v:Any, info:ValidationInfo)->Deployment:
        return SecurityContentObject.getDeploymentFromType(info.data.get("type",None), info)
        # director: Optional[DirectorOutputDto] = info.context.get("output_dto",None) 
        # if not director:
        #     raise ValueError("Cannot set deployment - DirectorOutputDto not passed to Detection Constructor in context")
        

        # typeField = info.data.get("type",None)

        # deps = [deployment for deployment in director.deployments if deployment.type == typeField]
        # if len(deps) == 1:
        #     return deps[0]
        # elif len(deps) == 0:
        #     raise ValueError(f"Failed to find Deployment for type '{typeField}' "\
        #                      f"from  possible {[deployment.type for deployment in director.deployments]}")
        # else:
        #     raise ValueError(f"Found more than 1 ({len(deps)}) Deployment for type '{typeField}' "\
        #                      f"from  possible {[deployment.type for deployment in director.deployments]}")


    @staticmethod
    def get_detections_from_filenames(detection_filenames:set[str], all_detections:list[Detection_Abstract])->list[Detection_Abstract]:
        detection_filenames = set(str(pathlib.Path(filename).absolute()) for filename in detection_filenames)
        detection_dict = SecurityContentObject.create_filename_to_content_dict(all_detections)

        try:
            return [detection_dict[detection_filename] for detection_filename in detection_filenames]
        except Exception as e:
            raise Exception(f"Failed to find detection object for modified detection: {str(e)}")
        

    # @validator("type")
    # def type_valid(cls, v, values):
    #     if v.lower() not in [el.name.lower() for el in AnalyticsType]:
    #         raise ValueError("not valid analytics type: " + values["name"])
    #     return v


    @field_validator('how_to_implement', 'known_false_positives', 'search')
    @classmethod
    def encode_error(cls, v: str, info: ValidationInfo):
        return SecurityContentObject.free_text_field_valid(v,info)

    
    @model_validator(mode="after")
    def addTags_nist(self):
        if self.type == AnalyticsType.TTP:
            self.tags.nist = [NistCategory.DE_CM]
        else:
            self.tags.nist = [NistCategory.DE_AE]
        return self

    @model_validator(mode="after")
    def search_observables_exist_validate(self):
        
        if isinstance(self.search, str):
            
            observable_fields = [ob.name.lower() for ob in self.tags.observable]
            
            #All $field$ fields from the message must appear in the search
            field_match_regex = r"\$([^\s.]*)\$"
            
            
            if self.tags.message:
                message_fields = [match.replace("$", "").lower() for match in re.findall(field_match_regex, self.tags.message.lower())]
                missing_fields = set([field for field in observable_fields if field not in self.search.lower()])
            else:
                message_fields = []
                missing_fields = set()
            

            error_messages = []
            if len(missing_fields) > 0:
                error_messages.append(f"The following fields are declared as observables, but do not exist in the search: {missing_fields}")

            
            missing_fields = set([field for field in message_fields if field not in self.search.lower()])
            if len(missing_fields) > 0:
                error_messages.append(f"The following fields are used as fields in the message, but do not exist in the search: {missing_fields}")
            
            if len(error_messages) > 0 and self.status == DetectionStatus.production.value:
                msg = "Use of fields in observables/messages that do not appear in search:\n\t- "+ "\n\t- ".join(error_messages)
                raise(ValueError(msg))
        
        # Found everything
        return self

    @model_validator(mode="after")
    def tests_validate(self):
        # Only Production detections are required to have test(s).
        # If the manual_test filed is defined, then the lack of test(s) is allowed.
        if self.status == DetectionStatus.production.value and not self.tags.manual_test and not self.tests:
            raise ValueError(
                "At least one test is REQUIRED for production detection: " + self.name
            )
        return self
        
    def all_tests_successful(self) -> bool:
        if len(self.tests) == 0:
            return False
        for test in self.tests:
            if test.result is None or test.result.success == False:
                return False
        return True

    def get_summary(
        self,
        detection_fields: list[str] = ["name", "search"],
        test_model_fields: list[str] = ["success", "message", "exception"],
        test_job_fields: list[str] = ["resultCount", "runDuration"],
    ) -> dict:
        summary_dict = {}
        for field in detection_fields:
            summary_dict[field] = getattr(self, field)
        summary_dict["success"] = self.all_tests_successful()
        summary_dict["tests"] = []
        for test in self.tests:
            result: dict[str, Union[str, bool]] = {"name": test.name}
            if test.result is not None:
                result.update(
                    test.result.get_summary_dict(
                        model_fields=test_model_fields,
                        job_fields=test_job_fields,
                    )
                )
            else:
                result["success"] = False
                result["message"] = "NO RESULT - Test not run"

            summary_dict["tests"].append(result)

        return summary_dict
