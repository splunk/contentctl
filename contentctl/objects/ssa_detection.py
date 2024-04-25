from __future__ import annotations
import uuid
import string
import requests
import time
from pydantic import BaseModel, validator, root_validator
from dataclasses import dataclass
from datetime import datetime
from typing import Union
import re

from contentctl.objects.abstract_security_content_objects.detection_abstract import Detection_Abstract
from contentctl.objects.enums import AnalyticsType
from contentctl.objects.enums import DataModel
from contentctl.objects.enums import DetectionStatus
from contentctl.objects.deployment import Deployment
from contentctl.objects.ssa_detection_tags import SSADetectionTags
from contentctl.objects.unit_test_ssa import UnitTestSSA
from contentctl.objects.unit_test_old import UnitTestOld
from contentctl.objects.macro import Macro
from contentctl.objects.lookup import Lookup
from contentctl.objects.baseline import Baseline
from contentctl.objects.playbook import Playbook
from contentctl.helper.link_validator import LinkValidator
from contentctl.objects.enums import SecurityContentType

class SSADetection(BaseModel):
    # detection spec
    name: str
    id: str
    version: int
    date: str
    author: str
    type: AnalyticsType = ...
    status: DetectionStatus = ...
    detection_type: str = None
    description: str
    data_source: list[str]
    search: Union[str, dict]
    how_to_implement: str
    known_false_positives: str
    references: list
    tags: SSADetectionTags
    tests: list[UnitTestSSA] = None

    # enrichments
    annotations: dict = None
    risk: list = None
    mappings: dict = None
    file_path: str = None
    source: str = None
    test: Union[UnitTestSSA, dict, UnitTestOld] = None
    runtime: str = None
    internalVersion: int = None

    # @validator('name')v
    # def name_max_length(cls, v, values):
    #     if len(v) > 67:
    #         raise ValueError('name is longer then 67 chars: ' + v)
    #     return v

    class Config:
        use_enum_values = True

    '''
    @validator("name")
    def name_invalid_chars(cls, v):
        invalidChars = set(string.punctuation.replace("-", ""))
        if any(char in invalidChars for char in v):
            raise ValueError("invalid chars used in name: " + v)
        return v

    @validator("id")
    def id_check(cls, v, values):
        try:
            uuid.UUID(str(v))
        except:
            raise ValueError("uuid is not valid: " + values["name"])
        return v

    @validator("date")
    def date_valid(cls, v, values):
        try:
            datetime.strptime(v, "%Y-%m-%d")
        except:
            raise ValueError("date is not in format YYYY-MM-DD: " + values["name"])
        return v

    # @validator("type")
    # def type_valid(cls, v, values):
    #     if v.lower() not in [el.name.lower() for el in AnalyticsType]:
    #         raise ValueError("not valid analytics type: " + values["name"])
    #     return v

    @validator("description", "how_to_implement")
    def encode_error(cls, v, values, field):
        try:
            v.encode("ascii")
        except UnicodeEncodeError:
            raise ValueError("encoding error in " + field.name + ": " + values["name"])
        return v

    # @root_validator
    # def search_validation(cls, values):
    #     if 'ssa_' not in values['file_path']:
    #         if not '_filter' in values['search']:
    #             raise ValueError('filter macro missing in: ' + values["name"])
    #         if any(x in values['search'] for x in ['eventtype=', 'sourcetype=', ' source=', 'index=']):
    #             if not 'index=_internal' in values['search']:
    #                 raise ValueError('Use source macro instead of eventtype, sourcetype, source or index in detection: ' + values["name"])
    #     return values

    @root_validator
    def name_max_length(cls, values):
        # Check max length only for ESCU searches, SSA does not have that constraint
        if "ssa_" not in values["file_path"]:
            if len(values["name"]) > 67:
                raise ValueError("name is longer then 67 chars: " + values["name"])
        return values


    @root_validator
    def new_line_check(cls, values):
        # Check if there is a new line in description and how to implement that is not escaped
        pattern = r'(?<!\\)\n' 
        if re.search(pattern, values["description"]):
            match_obj = re.search(pattern,values["description"])
            words = values["description"][:match_obj.span()[0]].split()[-10:]
            newline_context = ' '.join(words)
            raise ValueError(f"Field named 'description' contains new line that is not escaped using backslash. Add backslash at the end of the line after the words: '{newline_context}' in '{values['name']}'")
        if re.search(pattern, values["how_to_implement"]):
            match_obj = re.search(pattern,values["how_to_implement"])
            words = values["how_to_implement"][:match_obj.span()[0]].split()[-10:]
            newline_context = ' '.join(words)
            raise ValueError(f"Field named 'how_to_implement' contains new line that is not escaped using backslash. Add backslash at the end of the line after the words: '{newline_context}' in '{values['name']}'")
        return values

    # @validator('references')
    # def references_check(cls, v, values):
    #     return LinkValidator.SecurityContentObject_validate_references(v, values)


    @validator("search")
    def search_validate(cls, v, values):
        # write search validator
        return v

    @validator("tests")
    def tests_validate(cls, v, values):
        if (values.get("status","") in [DetectionStatus.production.value, DetectionStatus.validation.value]) and not v:
            raise ValueError(
                "At least one test is required for a production or validation detection: " + values["name"]
            )
        return v

    '''