from re import S
import uuid
import string
import requests
import time
import sys
import validators
import pathlib
import git
import os 
from pydantic import BaseModel, validator, root_validator
from dataclasses import dataclass
from datetime import datetime
from typing import Union



from bin.objects.security_content_object import SecurityContentObject
from bin.objects.enums import AnalyticsType
from bin.objects.enums import PostTestBehavior, DetectionTestingMode
from bin.objects.detection_tags import DetectionTags
from bin.objects.deployment import Deployment
from bin.objects.unit_test import UnitTest
from bin.objects.macro import Macro
from bin.objects.lookup import Lookup
from bin.objects.baseline import Baseline
from bin.objects.playbook import Playbook
from bin.helper.link_validator import LinkValidator
from bin.objects.app import App


ALWAYS_PULL = True

class TestConfig(BaseModel, SecurityContentObject):
    # detection spec
    path: str
    repo_url: str
    main_branch: str
    test_branch: str
    commit_hash: str
    container_name: str
    post_test_behavior: PostTestBehavior
    mode: str
    detections_list: Union[list[str], None] = None
    num_containers: int
    pr_number: int
    splunk_app_password: str
    mock:bool 
    splunkbase_username:str
    splunkbase_password:str
    apps: list[App]
    

    def validate_git_branch_name(self, name:str, object_type:str)->bool:
        #Get a list of all branches
        repo = git.Repo(self.path)
        all_branches = [branch.name for branch in repo.remote().refs]
        if name in all_branches:
            return True
        else:
            if ALWAYS_PULL:
                raise(ValueError(f"{object_type} {name} not found in repo located at {self.path}/{self.repo_url}"))
            else:
                raise(ValueError(f"{object_type} {name} not found in repo located at {self.path}/{self.repo_url}. "\
                    "If the branch is new, try pulling the repo."))


    @validator('path')
    def validate_path(cls,v):
        try:
            path = pathlib.Path(v)
        except Exception as e:
            raise(ValueError(f"Error, the provided path is is not a valid path: {v}"))
        try:
            r = git.Repo(path)
            
            
        except Exception as e:
            raise(ValueError(f"Error, the provided path is not a valid git repo: {path}"))
        
        try:
            if ALWAYS_PULL:
                r.remotes.origin.pull()
        except Exception as e:
            raise ValueError(f"Error pulling git repository {v}: {str(e)}")
        
    
        return v


    @validator('repo_url')
    def validate_repo_url(cls, v):
        try:
            validators.url(v)
        except:
            raise(ValueError(f"Error validating the repo_url: {v}"))
        return v

    @validator('main_branch')
    def valid_main_branch(cls, v):
        try:
            cls.validate_git_branch_name(v, "branch")
        except:
            raise ValueError(f"Error validating main git branch name: {v}")
        return v

    @validator('test_branch')
    def validate_test_branch(cls, v):
        try:
            cls.validate_git_branch_name(v, "branch")
        except:
            raise ValueError(f"Error validating main git branch name: {v}")
        return v

    @validator('hash')
    def validate_hash(cls, v):
        try:
            #We can a hash with this function too
            cls.validate_git_branch_name(v, "hash")
        except:
            raise ValueError(f"Error validating main git branch name: {v}")
        return v
    
    @validator('container_name')
    def validate_container_name(cls,v):
        #Stub to validate container name - should this actually pull
        #the container as well?  What is the best way to reconcile
        #between local images and images that are hosted somewhere
        #such as docker hub?
        return v
    
    #presumably the post test behavior is validated by the enum?
    #presumably the mode is validated by the enum? 
    
    @validator('detections_list')
    def validate_detections_list(cls, v, values):
        #A detections list can only be provided if the mode is selected
        #otherwise, we must throw an error

        #First check the mode
        if values['mode'] != DetectionTestingMode.selected:
            if v is not None:
                #We intentionally raise an error even if the list is an empty list
                raise(ValueError(f"For Detection Testing Mode {DetectionTestingMode.selected}, "\
                    f"'detections_list' MUST be none.  Instead, it was a list containing {len(v)} detections."))
        
        #Mode is DetectionTestingMode.selected - verify the paths of all the detections
        all_errors = []
        for detection in v:
            try:
                full_path = os.path.join(values['path'], detection)
                if not pathlib.Path(full_path).exists():
                    all_errors.append(full_path)
            except Exception as e:
                all_errors.append(f"Could not validate path '{detection}'")
        if len(all_errors):
            joined_errors = '\n\t'.join(all_errors)
            raise(Exception(ValueError(f"Paths to the following detections in 'detections_list' "\
                                        "were invalid: \n\t{joined_errors}")))

        
        return v

    



    @validator('datamodel')
    def datamodel_valid(cls, v, values):
        for datamodel in v:
            if datamodel not in [el.name for el in DataModel]:
                raise ValueError('not valid data model: ' + values["name"])
        return v

    @validator('description', 'how_to_implement')
    def encode_error(cls, v, values, field):
        try:
            v.encode('ascii')
        except UnicodeEncodeError:
            raise ValueError('encoding error in ' + field.name + ': ' + values["name"])
        return v

    @root_validator
    def search_validation(cls, values):
        if 'ssa_' not in values['file_path']:
            if not '_filter' in values['search']:
                raise ValueError('filter macro missing in: ' + values["name"])
            if any(x in values['search'] for x in ['eventtype=', 'sourcetype=', ' source=', 'index=']):
                if not 'index=_internal' in values['search']:
                    raise ValueError('Use source macro instead of eventtype, sourcetype, source or index in detection: ' + values["name"])
        return values

    @root_validator
    def name_max_length(cls, values):
        # Check max length only for ESCU searches, SSA does not have that constraint
        if 'ssa_' not in values['file_path']:
            if len(values["name"]) > 67:
                raise ValueError('name is longer then 67 chars: ' + values["name"])
        return values

# disable it because of performance reasons
    # @validator('references')
    # def references_check(cls, v, values):
    #     LinkValidator.check_references(v, values["name"])
    #     return v

    @validator('search')
    def search_validate(cls, v, values):
        # write search validator
        return v

 