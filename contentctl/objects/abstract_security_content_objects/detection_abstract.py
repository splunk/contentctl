from __future__ import annotations
from typing import TYPE_CHECKING,Union, Optional, List, Any, Annotated
import os.path
import re
import pathlib
from pydantic import BaseModel, field_validator, model_validator, ValidationInfo, Field, computed_field, model_serializer,ConfigDict, FilePath

from contentctl.objects.macro import Macro
from contentctl.objects.lookup import Lookup
if TYPE_CHECKING:
    from contentctl.input.director import DirectorOutputDto
    from contentctl.objects.baseline import Baseline
    
from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.enums import AnalyticsType
from contentctl.objects.enums import DataModel
from contentctl.objects.enums import DetectionStatus
from contentctl.objects.enums import NistCategory

from contentctl.objects.detection_tags import DetectionTags
from contentctl.objects.deployment import Deployment
from contentctl.objects.unit_test import UnitTest
from contentctl.objects.test_group import TestGroup
from contentctl.objects.integration_test import IntegrationTest
from contentctl.objects.event_source import EventSource
from contentctl.objects.data_source import DataSource

#from contentctl.objects.playbook import Playbook
from contentctl.objects.enums import ProvidingTechnology
from contentctl.enrichments.cve_enrichment import CveEnrichmentObj

MISSING_SOURCES:set[str] = set()

class Detection_Abstract(SecurityContentObject):
    model_config = ConfigDict(use_enum_values=True)
    
    #contentType: SecurityContentType = SecurityContentType.detections
    type: AnalyticsType = Field(...)
    status: DetectionStatus = Field(...)
    data_source: list[str] = []
    tags: DetectionTags = Field(...)
    search: Union[str, dict[str,Any]] = Field(...)
    how_to_implement: str = Field(..., min_length=4)
    known_false_positives: str = Field(..., min_length=4)

    enabled_by_default: bool = False
    file_path: FilePath = Field(...)
    # For model construction to first attempt construction of the leftmost object.
    # From a file, this should be UnitTest. Note this is different than the
    # default mode, 'smart'
    # https://docs.pydantic.dev/latest/concepts/unions/#left-to-right-mode
    # https://github.com/pydantic/pydantic/issues/9101#issuecomment-2019032541
    tests: List[Annotated[Union[UnitTest, IntegrationTest], Field(union_mode='left_to_right')]] = []
    # A list of groups of tests, relying on the same data
    test_groups: Union[list[TestGroup], None] = Field(None,validate_default=True)

    data_source_objects: list[DataSource] = []


    @field_validator("search", mode="before")
    @classmethod
    def validate_presence_of_filter_macro(cls, value:Union[str, dict[str,Any]], info:ValidationInfo)->Union[str, dict[str,Any]]:
        """
        Validates that, if required to be present, the filter macro is present with the proper name.
        The filter macro MUST be derived from the name of the detection


        Args:
            value (Union[str, dict[str,Any]]): The search. It can either be a string (and should be SPL) 
                                               or a dict, in which case it is Sigma-formatted.
            info (ValidationInfo): The validation info can contain a number of different objects. Today it only contains the director. 

        Returns:
            Union[str, dict[str,Any]]: The search, either in sigma or SPL format.
        """        
        
        if isinstance(value,dict):
            #If the search is a dict, then it is in Sigma format so return it
            return value
        
        # Otherwise, the search is SPL.
        
        
        # In the future, we will may add support that makes the inclusion of the 
        # filter macro optional or automatically generates it for searches that 
        # do not have it. For now, continue to require that all searches have a filter macro.
        FORCE_FILTER_MACRO = True
        if not FORCE_FILTER_MACRO:
            return value
        
        # Get the required macro name, which is derived from the search name.
        # Note that a separate validation ensures that the file name matches the content name
        name:Union[str,None] = info.data.get("name",None)
        if name is None:
            #The search was sigma formatted (or failed other validation and was None), so we will not validate macros in it
            raise ValueError("Cannot validate filter macro, field 'name' (which is required to validate the macro) was missing from the detection YML.")
        
        #Get the file name without the extension. Note this is not a full path!
        file_name = pathlib.Path(cls.contentNameToFileName(name)).stem
        file_name_with_filter = f"`{file_name}_filter`"
        
        if file_name_with_filter not in value:
            raise ValueError(f"Detection does not contain the EXACT filter macro {file_name_with_filter}. "
                             "This filter macro MUST be present in the search. It usually placed at the end "
                             "of the search and is useful for environment-specific filtering of False Positive or noisy results.")
        
        return value



    @field_validator("test_groups")
    @classmethod
    def validate_test_groups(cls, value:Union[None, List[TestGroup]], info:ValidationInfo) -> Union[List[TestGroup], None]:
        """
        Validates the `test_groups` field and constructs the model from the list of unit tests
        if no explicit construct was provided
        :param value: the value of the field `test_groups`
        :param values: a dict of the other fields in the Detection model
        """
        # if the value was not the None default, do nothing
        if value is not None:
            return value

        # iterate over the unit tests and create a TestGroup (and as a result, an IntegrationTest) for each
        test_groups: list[TestGroup] = []
        for unit_test in info.data.get("tests"):
            test_group = TestGroup.derive_from_unit_test(unit_test, info.data.get("name"))
            test_groups.append(test_group)

        # now add each integration test to the list of tests
        for test_group in test_groups:
            info.data.get("tests").append(test_group.integration_test)
        return test_groups


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

    deployment: Deployment = Field({})
    
    @computed_field
    @property
    def annotations(self)->dict[str,Union[List[str],int,str]]:

        annotations_dict:dict[str, Union[List[str], int]] = {} 
        annotations_dict["analytic_story"]=[story.name for story in self.tags.analytic_story]
        annotations_dict["confidence"] = self.tags.confidence
        if len(self.tags.cve or []) > 0:
            annotations_dict["cve"] = self.tags.cve        
        annotations_dict["impact"] = self.tags.impact
        annotations_dict["type"] = self.type
        #annotations_dict["version"] = self.version

        annotations_dict["data_source"] = self.data_source

        #The annotations object is a superset of the mappings object.
        # So start with the mapping object.
        annotations_dict.update(self.mappings)
        
        #Make sure that the results are sorted for readability/easier diffs
        return dict(sorted(annotations_dict.items(), key=lambda item: item[0]))
        
    #playbooks: list[Playbook] = []
    
    baselines: list[Baseline] = Field([],validate_default=True)
    
    @computed_field
    @property
    def mappings(self)->dict[str, List[str]]:
        mappings:dict[str,Any] = {}
        if len(self.tags.cis20) > 0:
            mappings["cis20"] = [tag.value for tag in self.tags.cis20]
        if len(self.tags.kill_chain_phases) > 0:
            mappings['kill_chain_phases'] = [phase.value for phase in self.tags.kill_chain_phases]
        if len(self.tags.mitre_attack_id) > 0:
            mappings['mitre_attack'] = self.tags.mitre_attack_id
        if len(self.tags.nist) > 0:
             mappings['nist'] = [category.value for category in self.tags.nist]
        
        
        # No need to sort the dict! It has been constructed in-order.
        # However, if this logic is changed, then consider reordering or
        # adding the sort back!
        #return dict(sorted(mappings.items(), key=lambda item: item[0]))
        return mappings

    macros: list[Macro] = Field([],validate_default=True)
    lookups: list[Lookup] = Field([],validate_default=True)

    cve_enrichment: list[CveEnrichmentObj] = Field([], validate_default=True)
    
    @model_validator(mode="after")
    def cve_enrichment_func(self, info:ValidationInfo):
        if len(self.cve_enrichment) > 0:
            raise ValueError(f"Error, field 'cve_enrichment' should be empty and "
                             f"dynamically populated at runtime. Instead, this field contained: {self.cve_enrichment}")

        output_dto:Union[DirectorOutputDto,None]= info.context.get("output_dto",None)
        if output_dto is None:
            raise ValueError("Context not provided to detection model post validator")
        
        
        enriched_cves:list[CveEnrichmentObj] = []

        for cve_id in self.tags.cve:
            try:
                enriched_cves.append(output_dto.cve_enrichment.enrich_cve(cve_id, raise_exception_on_failure=False))
            except Exception as e:
                raise ValueError(f"{e}")
        self.cve_enrichment = enriched_cves
        return self
    

    splunk_app_enrichment: Optional[List[dict]] = None
    
    @computed_field
    @property
    def nes_fields(self)->Optional[str]:
        if self.deployment.alert_action.notable is not None:
            return ','.join(self.deployment.alert_action.notable.nes_fields)
        else:
            return None
    
    @computed_field
    @property
    def providing_technologies(self)->List[ProvidingTechnology]:
        if isinstance(self.search, str):
            return ProvidingTechnology.getProvidingTechFromSearch(self.search)
        else:
            #Dict-formatted searches (sigma) will not have providing technologies
            return []
    
    @computed_field
    @property
    def risk(self)->list[dict[str,Any]]:
        risk_objects = []
        risk_object_user_types = {'user', 'username', 'email address'}
        risk_object_system_types = {'device', 'endpoint', 'hostname', 'ip address'}
        process_threat_object_types = {'process name','process'}
        file_threat_object_types = {'file name','file', 'file hash'}
        url_threat_object_types = {'url string','url'}
        ip_threat_object_types = {'ip address'}

        
        for entity in self.tags.observable:

            risk_object = dict()
            if 'Victim' in entity.role and entity.type.lower() in risk_object_user_types:
                risk_object['risk_object_type'] = 'user'
                risk_object['risk_object_field'] = entity.name
                risk_object['risk_score'] = self.tags.risk_score
                risk_objects.append(risk_object)

            elif 'Victim' in entity.role and entity.type.lower() in risk_object_system_types:
                risk_object['risk_object_type'] = 'system'
                risk_object['risk_object_field'] = entity.name
                risk_object['risk_score'] = self.tags.risk_score
                risk_objects.append(risk_object)

            elif 'Attacker' in entity.role and entity.type.lower() in process_threat_object_types:
                risk_object['threat_object_field'] = entity.name
                risk_object['threat_object_type'] = "process"
                risk_objects.append(risk_object) 

            elif 'Attacker' in entity.role and entity.type.lower() in file_threat_object_types:
                risk_object['threat_object_field'] = entity.name
                risk_object['threat_object_type'] = "file_name"
                risk_objects.append(risk_object) 

            elif 'Attacker' in entity.role and entity.type.lower() in ip_threat_object_types:
                risk_object['threat_object_field'] = entity.name
                risk_object['threat_object_type'] = "ip_address"
                risk_objects.append(risk_object) 

            elif 'Attacker' in entity.role and entity.type.lower() in url_threat_object_types:
                risk_object['threat_object_field'] = entity.name
                risk_object['threat_object_type'] = "url"
                risk_objects.append(risk_object) 

            else:
                risk_object['risk_object_type'] = 'other'
                risk_object['risk_object_field'] = entity.name
                risk_object['risk_score'] = self.tags.risk_score
                risk_objects.append(risk_object)
                continue


        return risk_objects

    
    
    @computed_field
    @property
    def metadata(self)->dict[str,str]:
        return {'detection_id':str(self.id),
                'deprecated':'1' if self.status==DetectionStatus.deprecated.value else '0',
                'detection_version':str(self.version)}

    @model_serializer
    def serialize_model(self):
        #Call serializer for parent
        super_fields = super().serialize_model()
        
        #All fields custom to this model
        model= {
            "tags": self.tags.model_dump(),
            "type": self.type,
            "search": self.search,
            "how_to_implement":self.how_to_implement,
            "known_false_positives":self.known_false_positives,
            "datamodel": self.datamodel,
            "source": self.source,
            "nes_fields": self.nes_fields,
        }
        #Only a subset of macro fields are required:
        all_macros = []
        for macro in self.macros:
            macro_dump:dict = {
                "name": macro.name,
                "definition": macro.definition,
                "description": macro.description
            }
            if len(macro.arguments) > 0:
                macro_dump['arguments'] = macro.arguments

            all_macros.append(macro_dump)
        model['macros'] = all_macros


        all_lookups = []
        for lookup in self.lookups:
            if lookup.collection is not None:
                all_lookups.append({
                                    "name":lookup.name,
                                    "description":lookup.description,
                                    "collection":lookup.collection,
                                    "case_sensitive_match": None,
                                    "fields_list":lookup.fields_list})
            elif lookup.filename is not None:
                all_lookups.append({
                                    "name":lookup.name,
                                    "description":lookup.description,
                                    "filename": lookup.filename.name,
                                    "default_match":"true" if lookup.default_match else "false",
                                    "case_sensitive_match": "true" if lookup.case_sensitive_match else "false",
                                    "match_type":lookup.match_type,
                                    "min_matches":lookup.min_matches,
                                    "fields_list":lookup.fields_list})
        model['lookups'] = all_lookups
        
        
        #Combine fields from this model with fields from parent
        super_fields.update(model)
        
        #return the model
        return super_fields


    def model_post_init(self, ctx:dict[str,Any]):
        # director: Optional[DirectorOutputDto] = ctx.get("output_dto",None)
        # if not isinstance(director,DirectorOutputDto):
        #     raise ValueError("DirectorOutputDto was not passed in context of Detection model_post_init")
        director: Optional[DirectorOutputDto] = ctx.get("output_dto",None)
        
        #Ensure that all baselines link to this detection
        for baseline in self.baselines:
            new_detections = []
            replaced = False
            for d in baseline.tags.detections:
                    if isinstance(d,str) and self.name==d:
                        new_detections.append(self)
                        replaced = True
                    else:
                        new_detections.append(d)
            if replaced is False:
                raise ValueError(f"Error, failed to replace detection reference in Baseline '{baseline.name}' to detection '{self.name}'")             
            baseline.tags.detections = new_detections

        # Data source may be defined 1 on each line, OR they may be defined as
        # SOUCE_1 AND ANOTHERSOURCE AND A_THIRD_SOURCE
        # if more than 1 data source is required for a detection (for example, because it includes a join)
        # Parse and update the list to resolve individual names and remove potential duplicates
        updated_data_source_names:set[str] = set()
        
        for ds in self.data_source:
            split_data_sources = {d.strip() for d in ds.split('AND')}
            updated_data_source_names.update(split_data_sources)
        
        sources = sorted(list(updated_data_source_names))
        
        matched_data_sources:list[DataSource] = []
        missing_sources:list[str] = []
        for source in sources:
            try:
                matched_data_sources += DataSource.mapNamesToSecurityContentObjects([source], director)
            except Exception as data_source_mapping_exception:
                # We gobble this up and add it to a global set so that we
                # can print it ONCE at the end of the build of datasources.
                # This will be removed later as per the note below
                MISSING_SOURCES.add(source)
                
        if len(missing_sources) > 0:
            # This will be changed to ValueError when we have a complete list of data sources
            print(f"WARNING: The following exception occurred when mapping the data_source field to DataSource objects:{missing_sources}")
        
        self.data_source_objects = matched_data_sources

        for story in self.tags.analytic_story:
            story.detections.append(self)            
        return self

    
    @field_validator('lookups',mode="before")
    @classmethod
    def getDetectionLookups(cls, v:list[str], info:ValidationInfo)->list[Lookup]:
        director:DirectorOutputDto = info.context.get("output_dto",None)
        
        search:Union[str,dict] = info.data.get("search",None)
        if not isinstance(search,str):
            #The search was sigma formatted (or failed other validation and was None), so we will not validate macros in it
            return []
        
        lookups= Lookup.get_lookups(search, director)
        return lookups

    @field_validator('baselines',mode="before")
    @classmethod
    def mapDetectionNamesToBaselineObjects(cls, v:list[str], info:ValidationInfo)->List[Baseline]:
        if len(v) > 0:
            raise ValueError("Error, baselines are constructed automatically at runtime.  Please do not include this field.")

        
        name:Union[str,None] = info.data.get("name",None)
        if name is None:
            raise ValueError("Error, cannot get Baselines because the Detection does not have a 'name' defined.")
         
        director:DirectorOutputDto = info.context.get("output_dto",None)
        baselines:List[Baseline] = []
        for baseline in director.baselines:
            # This matching is a bit strange, because baseline.tags.detections starts as a list of strings, but 
            # is eventually updated to a list of Detections as we construct all of the detection objects. 
            if name in [detection_name for detection_name in baseline.tags.detections if isinstance(detection_name,str)]:
                baselines.append(baseline)

        return baselines

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
            director.addContentToDictMappings(filter_macro)
        
        macros_from_search = Macro.get_macros(search, director)
        
        return  macros_from_search

    def get_content_dependencies(self)->list[SecurityContentObject]:
        #Do this separately to satisfy type checker
        objects: list[SecurityContentObject] = []
        objects += self.macros 
        objects += self.lookups     
        return objects
    
    
    @field_validator("deployment", mode="before")
    def getDeployment(cls, v:Any, info:ValidationInfo)->Deployment:
        return Deployment.getDeployment(v,info)
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

    
    @field_validator("enabled_by_default",mode="before")
    def only_enabled_if_production_status(cls,v:Any,info:ValidationInfo)->bool:
        '''
        A detection can ONLY be enabled by default if it is a PRODUCTION detection.
        If not (for example, it is EXPERIMENTAL or DEPRECATED) then we will throw an exception.
        Similarly, a detection MUST be schedulable, meaning that it must be Anomaly, Correleation, or TTP.
        We will not allow Hunting searches to be enabled by default.
        '''
        if v == False:
            return v
        
        status = DetectionStatus(info.data.get("status"))
        searchType = AnalyticsType(info.data.get("type"))
        errors = []
        if status != DetectionStatus.production:
            errors.append(f"status is '{status.name}'. Detections that are enabled by default MUST be '{DetectionStatus.production.value}'")
            
        if searchType not in [AnalyticsType.Anomaly, AnalyticsType.Correlation, AnalyticsType.TTP]:            
            errors.append(f"type is '{searchType.value}'. Detections that are enabled by default MUST be one of the following types: {[AnalyticsType.Anomaly.value, AnalyticsType.Correlation.value, AnalyticsType.TTP.value]}")
        if len(errors) > 0:
            error_message = "\n  - ".join(errors)
            raise ValueError(f"Detection is 'enabled_by_default: true' however \n  - {error_message}")
        
        return v
    

    @model_validator(mode="after")
    def addTags_nist(self):
        if self.type == AnalyticsType.TTP.value:
            self.tags.nist = [NistCategory.DE_CM]
        else:
            self.tags.nist = [NistCategory.DE_AE]
        return self
    
    @model_validator(mode="after")
    def ensureProperObservablesExist(self):
        """
        If a detections is PRODUCTION and either TTP or ANOMALY, then it MUST have an Observable with the VICTIM role.

        Returns:
            self: Returns itself if the valdiation passes 
        """
        if self.status not in [DetectionStatus.production.value]:
            # Only perform this validation on production detections
            return self

        if self.type not in [AnalyticsType.TTP.value, AnalyticsType.Anomaly.value]:
            # Only perform this validation on TTP and Anomaly detections
            return self 
    
        #Detection is required to have a victim
        roles = []
        for observable in self.tags.observable:
            roles.extend(observable.role)
        
        if roles.count("Victim") == 0:
            raise ValueError(f"Error, there must be AT LEAST 1 Observable with the role 'Victim' declared in Detection.tags.observables. However, none were found.")
        
        # Exactly one victim was found
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
        

    @model_validator(mode='after')
    def ensurePresenceOfRequiredTests(self):
        # TODO (cmcginley): Fix detection_abstract.tests_validate so that it surfaces validation errors
        #   (e.g. a lack of tests) to the final results, instead of just showing a failed detection w/
        #   no tests (maybe have a message propagated at the detection level? do a separate coverage
        #   check as part of validation?):
    
    
        #Only production analytics require tests
        if self.status != DetectionStatus.production.value:
            return self
        
        # All types EXCEPT Correlation MUST have test(s). Any other type, including newly defined types, requires them.
        # Accordingly, we do not need to do additional checks if the type is Correlation
        if self.type in set([AnalyticsType.Correlation.value]):
            return self
        
        if self.tags.manual_test is not None:
            for test in self.tests:
                test.skip(f"TEST SKIPPED: Detection marked as 'manual_test' with explanation: '{self.tags.manual_test}'")

        if len(self.tests) == 0:
            raise ValueError(f"At least one test is REQUIRED for production detection: {self.name}")
            

        return self

    @field_validator("tests")
    def tests_validate(cls, v, info:ValidationInfo):
        # TODO (cmcginley): Fix detection_abstract.tests_validate so that it surfaces validation errors
        #   (e.g. a lack of tests) to the final results, instead of just showing a failed detection w/
        #   no tests (maybe have a message propagated at the detection level? do a separate coverage
        #   check as part of validation?):
    
    
        #Only production analytics require tests
        if info.data.get("status","") != DetectionStatus.production.value:
            return v
        
        # All types EXCEPT Correlation MUST have test(s). Any other type, including newly defined types, requires them.
        # Accordingly, we do not need to do additional checks if the type is Correlation
        if info.data.get("type","") in set([AnalyticsType.Correlation.value]):
            return v
        
            
        # Ensure that there is at least 1 test        
        if len(v) == 0:
            if info.data.get("tags",None) and info.data.get("tags").manual_test is not None:
                # Detections that are manual_test MAY have detections, but it is not required.  If they
                # do not have one, then create one which will be a placeholder.
                # Note that this fake UnitTest (and by extension, Integration Test) will NOT be generated
                # if there ARE test(s) defined for a Detection.
                placeholder_test = UnitTest(name="PLACEHOLDER FOR DETECTION TAGGED MANUAL_TEST WITH NO TESTS SPECIFIED IN YML FILE", attack_data=[])
                return [placeholder_test]
            
            else:
                raise ValueError("At least one test is REQUIRED for production detection: " + info.data.get("name", "NO NAME FOUND"))


        #No issues - at least one test provided for production type requiring testing
        return v
        
    def all_tests_successful(self) -> bool:
        """
        Checks that all tests in the detection succeeded. If no tests are defined, consider that a
        failure; if any test fails (FAIL, ERROR), consider that a failure; if any test has
        no result or no status, consider that a failure. If all tests succeed (PASS, SKIP), consider
        the detection a success
        :returns: bool where True indicates all tests succeeded (they existed, complete and were
            PASS/SKIP)
        """
        # If no tests are defined, we consider it a failure for the detection
        if len(self.tests) == 0:
            return False

        # Iterate over tests
        for test in self.tests:
            # Check that test.result is not None
            if test.result is not None:
                # Check status is set (complete)
                if test.result.complete:
                    # Check for failure (FAIL, ERROR)
                    if test.result.failed:
                        return False
                else:
                    # If no stauts, return False
                    return False
            else:
                # If no result, return False
                return False

        # If all tests are successful (PASS/SKIP), return True
        return True

    def get_summary(
        self,
        detection_fields: list[str] = ["name", "search"],
        test_result_fields: list[str] = ["success", "message", "exception", "status", "duration", "wait_duration"],
        test_job_fields: list[str] = ["resultCount", "runDuration"],
    ) -> dict:
        """
        Aggregates a dictionary summarizing the detection model, including all test results
        :param detection_fields: the fields of the top level detection to gather
        :param test_result_fields: the fields of the test result(s) to gather
        :param test_job_fields: the fields of the test result(s) job content to gather
        :returns: a dict summary
        """
        # Init the summary dict
        summary_dict = {}

        # Grab the top level detection fields
        for field in detection_fields:
            summary_dict[field] = getattr(self, field)

        # Set success based on whether all tests passed
        summary_dict["success"] = self.all_tests_successful()

        # Aggregate test results
        summary_dict["tests"] = []
        for test in self.tests:
            # Initialize the dict as a mapping of strings to str/bool
            result: dict[str, Union[str, bool]] = {
                "name": test.name,
                "test_type": test.test_type.value
            }

            # If result is not None, get a summary of the test result w/ the requested fields
            if test.result is not None:
                result.update(
                    test.result.get_summary_dict(
                        model_fields=test_result_fields,
                        job_fields=test_job_fields,
                    )
                )
            else:
                # If no test result, consider it a failure
                result["success"] = False
                result["message"] = "NO RESULT - Test not run"

            # Add the result to our list
            summary_dict["tests"].append(result)

        # Return the summary

        return summary_dict


    def getMetadata(self)->dict[str,str]:
        return {'detection_id':str(self.id),
                'deprecated':'1' if self.status==DetectionStatus.deprecated.value else '0',
                'detection_version':str(self.version)}


