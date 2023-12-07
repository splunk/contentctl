from __future__ import annotations

import uuid
import string
import requests
import time
import sys
import re
import pathlib
from pydantic import BaseModel, field_validator, model_validator, ValidationInfo
from dataclasses import dataclass
from typing import Union, Optional, List
from datetime import datetime, timedelta


from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.enums import AnalyticsType
from contentctl.objects.enums import DataModel
from contentctl.objects.enums import DetectionStatus
from contentctl.objects.detection_tags import DetectionTags
from contentctl.objects.config import ConfigDetectionConfiguration
from contentctl.objects.unit_test import UnitTest
from contentctl.objects.macro import Macro
from contentctl.objects.lookup import Lookup
from contentctl.objects.baseline import Baseline
from contentctl.objects.playbook import Playbook
from contentctl.helper.link_validator import LinkValidator
from contentctl.objects.enums import SecurityContentType


class Detection_Abstract(SecurityContentObject):
    #contentType: SecurityContentType = SecurityContentType.detections
    type: AnalyticsType = ...
    status: DetectionStatus = ...
    data_source: Optional[List[]] = None
    tags: DetectionTags
    search: Union[str, dict]
    how_to_implement: str = ...
    known_false_positives: str = ...
    check_references: bool = False  
    
    tests: list[UnitTest] = []

    # enrichments
    datamodel: list = None
    deployment: ConfigDetectionConfiguration = None
    annotations: dict = None
    risk: list = None
    playbooks: list[Playbook] = []
    baselines: list[Baseline] = []
    mappings: dict = None
    macros: list[Macro] = []
    lookups: list[Lookup] = []
    cve_enrichment: list = None
    splunk_app_enrichment: list = None
    
    source: str = None
    nes_fields: str = None
    providing_technologies: list = None
    runtime: str = None

    class Config:
        use_enum_values = True


    def get_content_dependencies(self)->list[SecurityContentObject]:
        #Do this separately to satisfy type checker
        objects: list[SecurityContentObject] = []
        objects += self.playbooks 
        objects += self.baselines
        objects += self.macros 
        objects += self.lookups     
        return objects
    
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

    @field_validator('search')
    @classmethod
    def encode_error_search(cls, v: Union[str,dict], info: ValidationInfo):
        if isinstance(v,dict):
            #This is a special case of the search field.  It can be a dict, containing
            #a sigma search, if we are running the converter. So we will not
            #validate the field further. Additional validation will be done
            #during conversion phase later on
            return v
        
        return SecurityContentObject.free_text_field_valid(cls,v,values,field)


    @field_validator('how_to_implement', 'known_false_positives')
    @classmethod
    def encode_error(cls, v: str, info: ValidationInfo):
        return SecurityContentObject.free_text_field_valid(v,info)

    @validator("status")
    def validation_for_ba_only(cls, v, values):
        # Ensure that only a BA detection can have status: validation
        p = pathlib.Path(values['file_path'])
        if v == DetectionStatus.validation.value:
            if p.name.startswith("ssa___"): 
                pass
            else:
                raise ValueError(f"The following is NOT an ssa_ detection, but has 'status: {v}' which may ONLY be used for ssa_ detections: {values['file_path']}")
        
        return v
    
    @validator("search")
    def search_obsersables_exist_validate(cls, v, values):
        if type(v) is str:
            tags:DetectionTags = values.get("tags")
            if tags == None:
                raise ValueError("Unable to parse Detection Tags.  Please resolve Detection Tags errors")
            
            observable_fields = [ob.name.lower() for ob in tags.observable]
            
            #All $field$ fields from the message must appear in the search
            field_match_regex = r"\$([^\s.]*)\$"
            
            message_fields = [match.replace("$", "").lower() for match in re.findall(field_match_regex, tags.message.lower())]
            missing_fields = set([field for field in observable_fields if field not in v.lower()])

            error_messages = []
            if len(missing_fields) > 0:
                error_messages.append(f"The following fields are declared as observables, but do not exist in the search: {missing_fields}")

            
            missing_fields = set([field for field in message_fields if field not in v.lower()])
            if len(missing_fields) > 0:
                error_messages.append(f"The following fields are used as fields in the message, but do not exist in the search: {missing_fields}")
            
            if len(error_messages) > 0 and values.get("status") == DetectionStatus.production.value:
                msg = "\n\t".join(error_messages)
                raise(ValueError(msg))
        
        # Found everything
        return v

    @validator("tests")
    def tests_validate(cls, v, values):
        if values.get("status","") == DetectionStatus.production.value and not v:
            raise ValueError(
                "At least one test is REQUIRED for production detection: " + values["name"]
            )
        return v
    
    @validator("datamodel")
    def datamodel_valid(cls, v, values):
        for datamodel in v:
            if datamodel not in [el.name for el in DataModel]:
                raise ValueError("not valid data model: " + values["name"])
        return v
    
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
