from multiprocessing.sharedctypes import Value
from re import L, S
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
import docker


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
    test_branch: Union[str,None] = None
    commit_hash: Union[str,None] = None
    full_image_path: str = "registry.hub.docker.com/splunk/splunk:latest"
    container_name: str = "splunk_detection_testing_%d"
    post_test_behavior: PostTestBehavior
    mode: DetectionTestingMode = DetectionTestingMode.changes
    detections_list: Union[list[str], None] = None
    num_containers: int = 1
    pr_number: Union[int,None] = None
    splunk_app_password: Union[str,None] = None
    mock:bool 
    splunkbase_username:str
    splunkbase_password:str
    apps: list[App]
    


    def validate_git_hash(self, hash:str, branch_name:str)->bool:
        #Get a list of all branches
        repo = git.Repo(self.path)

        try:
            all_branches_containing_hash = repo.get.branch("--contains", hash).split('\n')
            #this is a list of all branches that contain the hash.  They are in the format:
            #* <some number of spaces> branchname (if the branch contains the hash)
            #<some number of spaces>   branchname (if the branch does not contain the hash)
            #Note, of course, that a hash can be in 0, 1, more branches!
            for branch_string in all_branches_containing_hash:
                if branch_string.split(' ')[0] == "*" and (branch_string.split(' ')[-1] == branch_name or branch_name==None):
                    #Yes, the hash exists in the branch!
                    return True
            #If we get here, it does not exist in the given branch
            raise(Exception("Does not exist in branch"))

        except Exception as e:
            if ALWAYS_PULL:
                raise(ValueError(f"hash '{hash} not found in branch '{branch_name}' for repo located at {self.path}/{self.repo_url}"))
            else:
                raise(ValueError(f"hash '{hash} not found in branch '{branch_name}' for repo located at {self.path}/{self.repo_url}\n"\
                                  "If the hash is new, try pulling the repo."))

    def validate_git_branch_name(self, name:str)->bool:
        #Get a list of all branches
        repo = git.Repo(self.path)
        
        all_branches = [branch.name for branch in repo.refs]
        #remove "origin/" from the beginning of each branch name
        all_branches = [branch.replace("origin/","") for branch in all_branches]


        if name in all_branches:
            return True
        
        else:
            if ALWAYS_PULL:
                raise(ValueError(f"branch '{name}' not found in repo located at {self.path}/{self.repo_url}"))
            else:
                raise(ValueError(f"branch '{name}' not found in repo located at {self.path}/{self.repo_url}\n"\
                    "If the branch is new, try pulling the repo."))
    
    def validate_git_pull_request(self, pr_number:int)->str:
        #Get a list of all branches
        repo = git.Repo(self.path)
        #List of all remotes that match this format.  If the PR exists, we
        #should find exactly one in the format SHA_HASH\tpull/pr_number/head
        pr_and_hash = repo.git.ls_remote("origin", f"pull/{pr_number}/head")
        if len(pr_and_hash) == 0:
            raise(ValueError(f"pr_number {pr_number} not found in Remote {repo.remote().url}"))
        elif len(pr_and_hash) > 1:
            raise(ValueError(f"Somehow, more than 1 PR was found with pr_number {pr_number}:\n{pr_and_hash}\nThis should not happen."))
        
        hash, _ = pr_and_hash.split('\t')
        return hash

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
    
    @validator('full_image_path')
    def validate_full_image_path(cls,v):
        #This behavior may change if we start supporting local/offline containers and 
        #the logic to build them
        if ':' not in v:
            raise(ValueError(f"Error, the image_name {v} does not include a tag.  A tagged container MUST be included to ensure consistency when testing"))
        if ALWAYS_PULL:
            #Check to make sure we have the latest version of the image
            try:
                client = docker.from_env()
                client.images.pull(v)
            except Exception as e:
                raise(ValueError(f"Error checking for the latest version of the image {v}: {str(e)}"))
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

    @validator('num_containers')
    def validate_num_containers(cls, v):
        if v < 1:
            raise(ValueError(f"Error validating num_containers. Test must be run with at least 1 container, not {v}"))
        return v

    @validator('pr_number')
    def validate_pr_number(cls, v, values):
        if v == None:
            return v
        
        hash = cls.validate_git_pull_request(v)
        #Ensure that the hash is equal to the one in the config file, if it exists.
        if values['commit_hash'] is None:
            values['commit_hash'] = hash
        else:
            if values['commit_hash'] != hash:
                raise(ValueError("commit_hash specified in configuration was {}, but commit_hash from pr_number {} was {}.  "\
                                 "These must match.  If you're testing a PR, you probably do NOT want to provide the "\
                                 "commit_hash in the configuration file and always want to test the head of the PR.  "\
                                 "This will be done automatically if you do not provide the commit_hash."))

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

 