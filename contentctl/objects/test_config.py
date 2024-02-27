# Needed for a staticmethod to be able to return an instance of the class it belongs to
from __future__ import annotations

import git
import pathlib
import yaml
from pydantic import BaseModel, field_validator, model_validator, Field, ValidationInfo, AnyHttpUrl, DirectoryPath, NonNegativeInt, FilePath, field_serializer
from typing import Any, Optional



from contentctl.objects.enums import (
    PostTestBehavior,
    DetectionTestingMode,
    DetectionTestingTargetInfrastructure,
)

from contentctl.helper.utils import Utils
from contentctl.objects.app import App

ALWAYS_PULL_REPO = False
PREVIOUSLY_ALLOCATED_PORTS: set[int] = set()

LOCAL_APP_DIR = pathlib.Path("apps")
CONTAINER_APP_DIR = pathlib.Path("/tmp/apps")


def getTestConfigFromYMLFile(path: pathlib.Path):
    try:
        with open(path, "r") as config_handle:
            cfg = yaml.safe_load(config_handle)
        return TestConfig.model_validate(cfg)

    except Exception as e:
        print(f"Error loading test configuration file '{path}': {str(e)}")


def serialize_url(url:AnyHttpUrl)->str:
    return str(url)

class Infrastructure(BaseModel, extra="forbid", validate_assignment=True):
    splunk_app_username: Optional[str] = Field(
        default="admin", title="The name of the user for testing"
    )
    splunk_app_password: Optional[str] = Field(
        default="password", title="Password for logging into Splunk Server"
    )
    instance_address: AnyHttpUrl = Field(
        default="http://127.0.0.1",
        title="Domain name of IP address of Splunk server to be used for testing. Do NOT use a protocol, like http(s):// or 'localhost'",
    )
    @field_serializer('instance_address')
    def serialize_address(self, repo_url: AnyHttpUrl, _info:ValidationInfo)->str:
        return serialize_url(repo_url)    
    
    instance_name: str = Field(
        default="Splunk_Server_Name",
        title="Template to be used for naming the Splunk Test Containers or referring to Test Servers.",
        pattern="[a-zA-Z0-9][a-zA-Z0-9_.-]*"
    )
    
    hec_port: int = Field(default=8088, gt=1, lt=65536, title="HTTP Event Collector Port")
    web_ui_port: int = Field(default=8000, gt=1, lt=65536, title="Web UI Port")
    api_port: int = Field(default=8089, gt=1, lt=65536, title="REST API Port")

    @staticmethod
    def get_infrastructure_containers(num_containers:int=1, splunk_app_username:str="admin", splunk_app_password:str="password", instance_name_template="splunk_contentctl_{index}")->list[Infrastructure]:
        containers:list[Infrastructure] = []
        if num_containers < 0:
            raise ValueError(f"Error - you must specifiy 1 or more containers, not {num_containers}.")

        #Get the starting ports
        i = Infrastructure() #Instantiate to get the base port numbers
        
        for index in range(0, num_containers):
            containers.append(Infrastructure(splunk_app_username=splunk_app_username,
                                             splunk_app_password=splunk_app_password,
                                             instance_name=instance_name_template.format(index=index),
                                             hec_port=i.hec_port+(index*2),
                                             web_ui_port=i.web_ui_port+index,
                                             api_port=i.api_port+(index*2)))

        
        return containers

    


    @model_validator(mode='before')
    @classmethod
    def validate_splunk_app_password(cls, data:Any) -> Any:
        if isinstance(data, dict):
            if not data.get("splunk_app_password",None):
                data["splunk_app_password"] = Utils.get_random_password()
        return data
    
    @model_validator(mode='after')
    def validate_ports_overlap(self)->Infrastructure:
        if len(set([self.hec_port, self.api_port, self.web_ui_port])) != 3:
               raise ValueError(f"Duplicate ports detected:\n\t"
                                 " web_ui_port: {self.web_port}\n\t"
                                 "    hec_port: {self.hec_port}\n\t"
                                 "    api_port: {self.api_port}")
        return self


class InfrastructureConfig(BaseModel, extra="forbid", validate_assignment=True):
    infrastructure_type: DetectionTestingTargetInfrastructure = Field(
        default=DetectionTestingTargetInfrastructure.container,
        title=f"Control where testing should be launched.  Choose one of {DetectionTestingTargetInfrastructure._member_names_}",
    )
    full_image_path: Optional[str] = Field(
        default="https://registry.hub.docker.com/splunk/splunk:latest",
        title="Full path to the container image to be used",
    )
    infrastructures: list[Infrastructure] = Field(default=[Infrastructure()],min_length=1)

    

    # @field_validator("infrastructure_type")
    # def validate_infrastructure_type(cls, v: DetectionTestingTargetInfrastructure, info: ValidationInfo):
    #     if v == DetectionTestingTargetInfrastructure.server:
    #         # No need to validate that the docker client is available
    #         return v
    #     elif v == DetectionTestingTargetInfrastructure.container:
    #         # we need to make sure we can actually get the docker client from the environment
    #         try:
    #             docker.client.from_env()
    #         except Exception as e:
    #             raise (
    #                 Exception(
    #                     f"Error, failed to get docker client.  Is Docker Installed and running "
    #                     f"and are docker environment variables set properly? Error:\n\t{str(e)}"
    #                 )
    #             )
    #     return v

    

    
    # @field_validator("full_image_path")
    # def validate_full_image_path(cls, v, values):
    #     if (
    #         values.get("infrastructure_type", None)
    #         == DetectionTestingTargetInfrastructure.server.value
    #     ):
    #         print(
    #             f"No need to validate target image path {v}, testing target is preconfigured server"
    #         )
    #         return v
    #     # This behavior may change if we start supporting local/offline containers and
    #     # the logic to build them
    #     if ":" not in v:
    #         raise (
    #             ValueError(
    #                 f"Error, the image_name {v} does not include a tag.  A tagged container MUST be included to ensure consistency when testing"
    #             )
    #         )

    #     # Check to make sure we have the latest version of the image
    #     # We have this as a wrapped, nested try/except because if we
    #     # encounter some error in trying to get the latest version, but
    #     # we do have some version already, we will allow the test to continue.
    #     # For example, this may occur if an image has been previously downloaded,
    #     # but the server no longer has internet connectivity and can't get the
    #     # image again. in this case, don't fail - continue with the test
    #     try:
    #         try:
    #             # connectivity to docker server is validated previously
    #             client = docker.from_env()
    #             print(
    #                 f"Getting the latest version of the container image: {v}...",
    #                 end="",
    #                 flush=True,
    #             )
    #             client.images.pull(v, platform="linux/amd64")
    #             print("done")
    #         except docker.errors.APIError as e:
    #             print("error")
    #             if e.is_client_error():
    #                 if "invalid reference format" in str(e.explanation):
    #                     simple_explanation = f"The format of the docker image reference is incorrect. Please use a valid image reference"
    #                 else:
    #                     simple_explanation = (
    #                         f"The most likely cause of this error is that the image/tag "
    #                         "does not exist or it is stored in a private repository and you are not logged in."
    #                     )

    #             elif e.is_server_error():
    #                 simple_explanation = (
    #                     f"The mostly likely cause is that the server cannot be reached. "
    #                     "Please ensure that the server hosting your docker image is available "
    #                     "and you have internet access, if required."
    #                 )

    #             else:
    #                 simple_explanation = f"Unable to pull image {v} for UNKNOWN reason. Please consult the detailed error below."

    #             verbose_explanation = e.explanation

    #             raise (
    #                 ValueError(
    #                     f"Error Pulling Docker Image '{v}'\n  - EXPLANATION: {simple_explanation} (full error text: '{verbose_explanation}'"
    #                 )
    #             )
    #         except Exception as e:
    #             print("error")
    #             raise (ValueError(f"Uknown error pulling Docker Image '{v}': {str(e)}"))

    #     except Exception as e:
    #         # There was some exception that prevented us from getting the latest version
    #         # of the image. However, if we already have it, use the current version and
    #         # down fully raise the exception - just use it
    #         client = docker.from_env()
    #         try:
    #             client.api.inspect_image(v)
    #             print(e)
    #             print(
    #                 f"We will default to using the version of the image {v} which has "
    #                 "already been downloaded to this machine. Please note that it may be out of date."
    #             )

    #         except Exception as e2:
    #             raise (
    #                 ValueError(
    #                     f"{str(e)}Image is not previously cached, so we could not use an old version."
    #                 )
    #             )

    #     return v

    @model_validator(mode="after")
    def validate_ports_overlap(self)->InfrastructureConfig:
        ports = set()
        if self.infrastructure_type == DetectionTestingTargetInfrastructure.server.value:
            #ports are allowed to overlap, they are on different servers
            return self

        for infrastructure in self.infrastructures:
            for k in ["hec_port", "web_ui_port", "api_port"]:
                if getattr(infrastructure, k) in ports:
                    raise ValueError(f"Port {getattr(infrastructure, k)} used more than once in container infrastructure ports")
                ports.add(getattr(infrastructure, k))
        return self
    
class VersionControlConfig(BaseModel, extra='forbid', validate_assignment=True):
    repo_path: DirectoryPath = Field(default=".", title="Path to the root of your app")
    repo_url: Optional[AnyHttpUrl] = Field(None,title="HTTP(s) path to the repo for repo_path.  If this field is blank, it will be inferred from the repo",
    )
    target_branch: Optional[str] = Field(None,title="Main branch of the repo or target of a Pull Request/Merge Request.")
    test_branch: Optional[str] = Field(None, title="Branch of the repo to be tested, if applicable.")
    commit_hash: Optional[str] = Field(None, title="Commit hash of the repo state to be tested, if applicable")
    pr_number: Optional[NonNegativeInt] = Field(None, title="The number of the PR to test")


    @field_serializer('repo_url')
    def serialize_address(self, repo_url: AnyHttpUrl, _info:ValidationInfo)->str:
        return serialize_url(repo_url)    
    
    @field_validator('repo_path')
    @classmethod
    def validate_repo_path(cls, v: DirectoryPath, info: ValidationInfo):
        if not v.is_dir():
            raise(ValueError(f"Error, the provided path is is not a valid path: '{v}'"))

        try:
            r = git.Repo(v)
        except Exception as e:
            raise(ValueError(f"Error, the provided path is not a valid git repo: '{v}'"))

        try:

            if ALWAYS_PULL_REPO:
                r.remotes.origin.pull()
        except Exception as e:
            raise ValueError(f"Error pulling git repository {v}: {str(e)}")
        print("repo path looks good")
        return v

    @model_validator(mode="after")
    def validate_repo_url(self)->VersionControlConfig:
        #First try to get the value from the repo
        try:
            remotes = git.Repo(self.repo_path).remotes
        except Exception as e:
            raise ValueError(f"Error - repo at {self.repo_path} has no remotes.  Repo MUST be tracked in a remote git repo.")
        
        try:
            remote_url_from_repo = AnyHttpUrl(remotes.origin.url)
        except Exception as e:
            raise(ValueError(f"Error reading remote_url from the repo located at '{self.repo_path}'"))

        if self.repo_url is not None and remote_url_from_repo != self.repo_url:
            raise(ValueError(f"The url of the remote repo supplied in the config file {self.repo_url} does not "\
                              f"match the value read from the repository at {self.repo_path}, {remote_url_from_repo}"))

        if self.repo_url is None:
            self.repo_url = remote_url_from_repo

        return self
    

    @model_validator(mode='after')
    def check_branches(self) -> VersionControlConfig:
        r = git.Repo(self.repo_path)

        if not self.target_branch:
            self.target_branch = Utils.get_default_branch_name(str(self.repo_path), str(self.repo_url))
        else:
            try:
                Utils.validate_git_branch_name(str(self.repo_path), str(self.repo_url), self.target_branch)
            except Exception as e:
                raise ValueError(f"Error validating existence of target_branch: {str(e)}")
            
        if not self.test_branch:
            self.test_branch = r.active_branch.name
        else:
            try:
                Utils.validate_git_branch_name(str(self.repo_path), str(self.repo_url),self.test_branch)
            except Exception as e:
                raise ValueError(f"Error validating existence of test_branch: {str(e)}")
        
        #Check out the test branch
        r.git.checkout(self.test_branch)
            
        return self
    
    # TODO: Implement commit hash and PR/MR support
    # @validator('commit_hash')
    # def validate_commit_hash(cls, v, values):
    #     try:
    #         #We can a hash with this function too
    #         Utils.validate_git_hash(values['repo_path'],values['repo_url'], v, values['test_branch'])
    #     except Exception as e:
    #         raise ValueError(f"Error validating commit_hash '{v}': {str(e)}")
    #     return v
    
    # @validator('pr_number')
    # def validate_pr_number(cls, v, values):
    #     if v == None:
    #         return v

    #     hash = Utils.validate_git_pull_request(values['repo_path'], v)

    #     #Ensure that the hash is equal to the one in the config file, if it exists.
    #     if values['commit_hash'] is None:
    #         values['commit_hash'] = hash
    #     else:
    #         if values['commit_hash'] != hash:
    #             raise(ValueError(f"commit_hash specified in configuration was {values['commit_hash']}, but commit_hash"\
    #                              f" from pr_number {v} was {hash}. These must match.  If you're testing"\
    #                              " a PR, you probably do NOT want to provide the commit_hash in the configuration file "\
    #                              "and always want to test the head of the PR. This will be done automatically if you do "\
    #                              "not provide the commit_hash."))

    #     return v

    
class TestConfig(BaseModel, extra="forbid", validate_assignment=True):
    
    version_control_config: Optional[VersionControlConfig] = Field(None, title="Basic version control information for contentctl test modes.")
    
    infrastructure_config: InfrastructureConfig = Field(
        default=InfrastructureConfig(),
        title=f"The infrastructure for testing to be run on",
    )
    
    
    post_test_behavior: PostTestBehavior = Field(
        default=PostTestBehavior.pause_on_failure,
        title=f"What to do after a test has completed.  Choose one of {PostTestBehavior._member_names_}",
    )
    mode: DetectionTestingMode = Field(
        default=DetectionTestingMode.all,
        title=f"Control which detections should be tested.  Choose one of {DetectionTestingMode._member_names_}",
    )
    detections_list: Optional[list[FilePath]] = Field(
        default=None, title="List of paths to detections which should be tested"
    )
    
    
    splunkbase_username: Optional[str] = Field(
        default=None,
        title="The username for logging into Splunkbase in case apps must be downloaded",
    )
    splunkbase_password: Optional[str] = Field(
        default=None,
        title="The password for logging into Splunkbase in case apps must be downloaded",
    )
    apps: list[App] = Field(
        default=App.get_default_apps(),
        title="A list of all the apps to be installed on each container",
    )
    

    # # Ensure that at least 1 of test_branch, commit_hash, and/or pr_number were passed.
    # # Otherwise, what are we testing??
    # # @root_validator(pre=False)
    # def ensure_there_is_something_to_test(cls, values):
    #     if 'test_branch' not in values and 'commit_hash' not in values and'pr_number' not in values:
    #         if 'mode' in values and values['mode'] == DetectionTestingMode.changes:
    #             raise(ValueError(f"Under mode [{DetectionTestingMode.changes}], 'test_branch', 'commit_hash', and/or 'pr_number' must be defined so that we know what to test."))

    #     return values

    

    @model_validator(mode='after')
    def check_splunkbase_username_password(self)->TestConfig:
        if self.splunkbase_username and self.splunkbase_password:
            return self
        elif not self.splunkbase_username and not self.splunkbase_password:
            return self
        else:
            if self.splunkbase_username:
                raise ValueError("splunkbase_username was provided, but splunkbase_password was not. You must provide both or neither.")
            else:
                raise ValueError("splunkbase_password was provided, but splunkbase_username was not. You must provide both or neither.")


    # @validator("apps",)
    # def validate_apps(cls, v, values):
        

    #     app_errors = []

    #     # ensure that the splunkbase username and password are provided
    #     username = values["splunkbase_username"]
    #     password = values["splunkbase_password"]
    #     app_directory = LOCAL_APP_DIR
    #     try:
    #         os.makedirs(LOCAL_APP_DIR, exist_ok=True)
    #     except Exception as e:
    #         raise (
    #             Exception(f"Error: When trying to create {CONTAINER_APP_DIR}: {str(e)}")
    #         )

    #     for app in v:
    #         if app.environment_path != ENVIRONMENT_PATH_NOT_SET:
    #             #Avoid re-configuring the apps that have already been configured.
    #             continue

    #         try:
    #             app.configure_app_source_for_container(
    #                 username, password, app_directory, CONTAINER_APP_DIR
    #             )
    #         except Exception as e:
    #             error_string = f"Unable to prepare app '{app.title}': {str(e)}"
    #             app_errors.append(error_string)

    #     if len(app_errors) != 0:
    #         error_string = "\n\t".join(app_errors)
    #         raise (ValueError(f"Error preparing apps to install:\n\t{error_string}"))

    #     return v

    