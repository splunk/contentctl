# Needed for a staticmethod to be able to return an instance of the class it belongs to
from __future__ import annotations

import git
import validators
import pathlib
import yaml
import os
from pydantic import BaseModel, validator, root_validator, Extra, Field
from typing import Union
import re
import docker
import docker.errors


from contentctl.objects.enums import (
    PostTestBehavior,
    DetectionTestingMode,
    DetectionTestingTargetInfrastructure,
)

from contentctl.objects.app import App, ENVIRONMENT_PATH_NOT_SET
from contentctl.helper.utils import Utils


ALWAYS_PULL_REPO = False
PREVIOUSLY_ALLOCATED_PORTS: set[int] = set()

LOCAL_APP_DIR = pathlib.Path("apps")
CONTAINER_APP_DIR = pathlib.Path("/tmp/apps")


def getTestConfigFromYMLFile(path: pathlib.Path):
    try:
        with open(path, "r") as config_handle:
            cfg = yaml.safe_load(config_handle)
        return TestConfig.parse_obj(cfg)

    except Exception as e:
        print(f"Error loading test configuration file '{path}': {str(e)}")


class Infrastructure(BaseModel, extra=Extra.forbid, validate_assignment=True):
    splunk_app_username: Union[str, None] = Field(
        default="admin", title="The name of the user for testing"
    )
    splunk_app_password: Union[str, None] = Field(
        default="password", title="Password for logging into Splunk Server"
    )
    instance_address: str = Field(
        default="127.0.0.1",
        title="Domain name of IP address of Splunk server to be used for testing. Do NOT use a protocol, like http(s):// or 'localhost'",
    )
    
    instance_name: str = Field(
        default="Splunk_Server_Name",
        title="Template to be used for naming the Splunk Test Containers or referring to Test Servers.",
    )
    
    hec_port: int = Field(default=8088, title="HTTP Event Collector Port")
    web_ui_port: int = Field(default=8000, title="Web UI Port")
    api_port: int = Field(default=8089, title="REST API Port")

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

    @validator("instance_name")
    def validate_instance_name(cls,v,values):
        if not re.fullmatch("[a-zA-Z0-9][a-zA-Z0-9_.-]*", v):
            raise ValueError(f"The instance_name '{v}' is not valid.  Please use an instance name which matches the regular expression '[a-zA-Z0-9][a-zA-Z0-9_.-]*'")
        else:
            return v
        
    @validator("instance_address")
    def validate_instance_address(cls, v, values):
        try:
            if v.startswith("http"):
                raise (Exception("should not begin with http"))
            is_ipv4 = validators.ipv4(v)
            if bool(is_ipv4):
                return v
            is_domain_name = validators.domain(v)
            if bool(is_domain_name):
                import socket

                try:
                    socket.gethostbyname(v)
                    return v
                except Exception as e:
                    pass
                raise (Exception("DNS Lookup failed"))
            raise (Exception(f"not an IPV4 address or a domain name"))
        except Exception as e:
            raise (
                Exception(
                    f"Error, failed to validate instance_address '{v}': {str(e)}"
                )
            )



    @validator("splunk_app_password")
    def validate_splunk_app_password(cls, v):
        if v == None:
            # No app password was provided, so generate one
            v = Utils.get_random_password()
        else:
            MIN_PASSWORD_LENGTH = 6
            if len(v) < MIN_PASSWORD_LENGTH:
                raise (
                    ValueError(
                        f"Password is less than {MIN_PASSWORD_LENGTH} characters long. This password is extremely weak, please change it."
                    )
                )
        return v

    @validator("hec_port", "web_ui_port", "api_port", each_item=True)
    def validate_ports_range(cls, v):
        if v < 2:
            raise (
                ValueError(
                    f"Error, invalid Port number. Port must be between 2-65535: {v}"
                )
            )
        elif v > 65535:
            raise (
                ValueError(
                    f"Error, invalid Port number. Port must be between 2-65535: {v}"
                )
            )
        return v
    
    @validator("hec_port", "web_ui_port", "api_port", each_item=False)
    def validate_ports_overlap(cls, v):
        
        if type(v) is not list:
            # Otherwise this throws error when we update a single field
            return v
        if len(set(v)) != len(v):
            raise (ValueError(f"Duplicate ports detected: [{v}]"))

        return v

class InfrastructureConfig(BaseModel, extra=Extra.forbid, validate_assignment=True):
    infrastructure_type: DetectionTestingTargetInfrastructure = Field(
        default=DetectionTestingTargetInfrastructure.container,
        title=f"Control where testing should be launched.  Choose one of {DetectionTestingTargetInfrastructure._member_names_}",
    )

    persist_and_reuse_container:bool = True

    full_image_path: str = Field(
        default="registry.hub.docker.com/splunk/splunk:latest",
        title="Full path to the container image to be used",
    )
    infrastructures: list[Infrastructure] = []

    
    @validator("infrastructure_type")
    def validate_infrastructure_type(cls, v, values):
        if v == DetectionTestingTargetInfrastructure.server:
            # No need to validate that the docker client is available
            return v
        elif v == DetectionTestingTargetInfrastructure.container:
            # we need to make sure we can actually get the docker client from the environment
            try:
                docker.client.from_env()
            except Exception as e:
                raise (
                    Exception(
                        f"Error, failed to get docker client.  Is Docker Installed and running "
                        f"and are docker environment variables set properly? Error:\n\t{str(e)}"
                    )
                )
        return v

    

    
    @validator("full_image_path")
    def validate_full_image_path(cls, v, values):
        if (
            values.get("infrastructure_type", None)
            == DetectionTestingTargetInfrastructure.server.value
        ):
            print(
                f"No need to validate target image path {v}, testing target is preconfigured server"
            )
            return v
        # This behavior may change if we start supporting local/offline containers and
        # the logic to build them
        if ":" not in v:
            raise (
                ValueError(
                    f"Error, the image_name {v} does not include a tag.  A tagged container MUST be included to ensure consistency when testing"
                )
            )

        # Check to make sure we have the latest version of the image
        # We have this as a wrapped, nested try/except because if we
        # encounter some error in trying to get the latest version, but
        # we do have some version already, we will allow the test to continue.
        # For example, this may occur if an image has been previously downloaded,
        # but the server no longer has internet connectivity and can't get the
        # image again. in this case, don't fail - continue with the test
        try:
            try:
                # connectivity to docker server is validated previously
                client = docker.from_env()
                print(
                    f"Getting the latest version of the container image: {v}...",
                    end="",
                    flush=True,
                )
                client.images.pull(v, platform="linux/amd64")
                print("done")
            except docker.errors.APIError as e:
                print("error")
                if e.is_client_error():
                    if "invalid reference format" in str(e.explanation):
                        simple_explanation = f"The format of the docker image reference is incorrect. Please use a valid image reference"
                    else:
                        simple_explanation = (
                            f"The most likely cause of this error is that the image/tag "
                            "does not exist or it is stored in a private repository and you are not logged in."
                        )

                elif e.is_server_error():
                    simple_explanation = (
                        f"The mostly likely cause is that the server cannot be reached. "
                        "Please ensure that the server hosting your docker image is available "
                        "and you have internet access, if required."
                    )

                else:
                    simple_explanation = f"Unable to pull image {v} for UNKNOWN reason. Please consult the detailed error below."

                verbose_explanation = e.explanation

                raise (
                    ValueError(
                        f"Error Pulling Docker Image '{v}'\n  - EXPLANATION: {simple_explanation} (full error text: '{verbose_explanation}'"
                    )
                )
            except Exception as e:
                print("error")
                raise (ValueError(f"Uknown error pulling Docker Image '{v}': {str(e)}"))

        except Exception as e:
            # There was some exception that prevented us from getting the latest version
            # of the image. However, if we already have it, use the current version and
            # down fully raise the exception - just use it
            client = docker.from_env()
            try:
                client.api.inspect_image(v)
                print(e)
                print(
                    f"We will default to using the version of the image {v} which has "
                    "already been downloaded to this machine. Please note that it may be out of date."
                )

            except Exception as e2:
                raise (
                    ValueError(
                        f"{str(e)}Image is not previously cached, so we could not use an old version."
                    )
                )

        return v

    @validator("infrastructures", always=True)
    def validate_infrastructures(cls, v, values):
        MAX_RECOMMENDED_CONTAINERS_BEFORE_WARNING = 2
        if values.get("infrastructure_type",None) == DetectionTestingTargetInfrastructure.container and len(v) == 0:
            v = [Infrastructure()]

        if len(v) < 1:
            #print("Fix number of infrastructure validation later")
            return v
            raise (
                ValueError(
                    f"Error validating infrastructures.  Test must be run with AT LEAST 1 infrastructure, not {len(v)}"
                )
            )
        if (values.get("infrastructure_type", None) == DetectionTestingTargetInfrastructure.container.value) and len(v) > MAX_RECOMMENDED_CONTAINERS_BEFORE_WARNING:
            print(
                f"You requested to run with [{v}] containers which may use a very large amount of resources "
                "as they all run in parallel.  The maximum suggested number of parallel containers is "
                f"[{MAX_RECOMMENDED_CONTAINERS_BEFORE_WARNING}].  We will do what you asked, but be warned!"
            )
        return v


    @validator("infrastructures", each_item=False)
    def validate_ports_overlap(cls, v, values):
        ports = set()
        if values.get("infrastructure_type", None) == DetectionTestingTargetInfrastructure.server.value:
            #ports are allowed to overlap, they are on different servers
            return v

        if len(v) == 0:
            raise ValueError("Error, there must be at least one test infrastructure defined in infrastructures.")
        for infrastructure in v:
            for k in ["hec_port", "web_ui_port", "api_port"]:
                if getattr(infrastructure, k) in ports:
                    raise ValueError(f"Port {getattr(infrastructure, k)} used more than once in container infrastructure ports")
                ports.add(getattr(infrastructure, k))
        return v
    
class VersionControlConfig(BaseModel, extra=Extra.forbid, validate_assignment=True):
    repo_path: str = Field(default=".", title="Path to the root of your app")
    repo_url: str = Field(
        default="https://github.com/your_organization/your_repo",
        title="HTTP(s) path to the repo for repo_path.  If this field is blank, it will be inferred from the repo",
    )
    target_branch: str = Field(default="main", title="Main branch of the repo or target of a Pull Request/Merge Request.")
    test_branch: str = Field(default="main", title="Branch of the repo to be tested, if applicable.")
    commit_hash: Union[str,None] = Field(default=None, title="Commit hash of the repo state to be tested, if applicable")
    pr_number: Union[int,None] = Field(default=None, title="The number of the PR to test")

    @validator('repo_path')
    def validate_repo_path(cls,v):
        print(f"checking repo path '{v}'")
        try:
            path = pathlib.Path(v)
        except Exception as e:
            
            raise(ValueError(f"Error, the provided path is is not a valid path: '{v}'"))

        try:
            r = git.Repo(path)
        except Exception as e:
            
            raise(ValueError(f"Error, the provided path is not a valid git repo: '{path}'"))

        try:

            if ALWAYS_PULL_REPO:
                r.remotes.origin.pull()
        except Exception as e:
            raise ValueError(f"Error pulling git repository {v}: {str(e)}")
        print("repo path looks good")
        return v

    @validator('repo_url')
    def validate_repo_url(cls, v, values):
        #First try to get the value from the repo
        try:
            remotes = git.Repo(values['repo_path']).remotes
        except Exception as e:
            raise ValueError(f"Error - repo at {values['repo_path']} has no remotes.  Repo must be tracked in a remote git repo.")
        
        try:
            remote_url_from_repo = remotes.origin.url
        except Exception as e:
            raise(ValueError(f"Error reading remote_url from the repo located at '{values['repo_path']}'"))

        if v is not None and remote_url_from_repo != v:
            raise(ValueError(f"The url of the remote repo supplied in the config file {v} does not "\
                              f"match the value read from the repository at {values['repo_path']}, {remote_url_from_repo}"))

        if v is None:
            v = remote_url_from_repo

        #Ensure that the url is the proper format
        # try:
        #     if bool(validators.url(v)) == False:
        #         raise(Exception)
        # except:
        #     raise(ValueError(f"Error validating the repo_url. The url is not valid: {v}"))

        return v
    
    @validator('target_branch')
    def valid_target_branch(cls, v, values):
        if v is None:
            print(f"target_branch is not supplied.  Inferring from '{values['repo_path']}'...",end='')

            target_branch = Utils.get_default_branch_name(values['repo_path'], values['repo_url'])
            print(f"target_branch name '{target_branch}' inferred'")
            #continue with the validation
            v = target_branch

        try:
            Utils.validate_git_branch_name(values['repo_path'],values['repo_url'], v)
        except Exception as e:
            raise ValueError(f"Error validating target_branch: {str(e)}")
        return v

    @validator('test_branch')
    def validate_test_branch(cls, v, values):
        if v is None:
            print(f"No test_branch provided, so we will default to using the target_branch '{values['target_branch']}'")
            v = values['target_branch']
        try:
            Utils.validate_git_branch_name(values['repo_path'],values['repo_url'], v)
        except Exception as e:
            raise ValueError(f"Error validating test_branch: {str(e)}")
        
        r = git.Repo(values.get("repo_path"))
        try:
            if r.active_branch.name != v:
                print(f"We are trying to test {v} but the current active branch is {r.active_branch}")
                print(f"Checking out {v}")
                r.git.checkout(v)
        except Exception as e:
            raise ValueError(f"Error checking out test_branch '{v}': {str(e)}")
        return v

    @validator('commit_hash')
    def validate_commit_hash(cls, v, values):
        try:
            #We can a hash with this function too
            Utils.validate_git_hash(values['repo_path'],values['repo_url'], v, values['test_branch'])
        except Exception as e:
            raise ValueError(f"Error validating commit_hash '{v}': {str(e)}")
        return v
    
    @validator('pr_number')
    def validate_pr_number(cls, v, values):
        if v == None:
            return v

        hash = Utils.validate_git_pull_request(values['repo_path'], v)

        #Ensure that the hash is equal to the one in the config file, if it exists.
        if values['commit_hash'] is None:
            values['commit_hash'] = hash
        else:
            if values['commit_hash'] != hash:
                raise(ValueError(f"commit_hash specified in configuration was {values['commit_hash']}, but commit_hash"\
                                 f" from pr_number {v} was {hash}. These must match.  If you're testing"\
                                 " a PR, you probably do NOT want to provide the commit_hash in the configuration file "\
                                 "and always want to test the head of the PR. This will be done automatically if you do "\
                                 "not provide the commit_hash."))

        return v

    
class TestConfig(BaseModel, extra=Extra.forbid, validate_assignment=True):
    
    version_control_config: Union[VersionControlConfig,None] = VersionControlConfig()
    
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
    detections_list: Union[list[str], None] = Field(
        default=None, title="List of paths to detections which should be tested"
    )
    
    
    splunkbase_username: Union[str, None] = Field(
        default=None,
        title="The username for logging into Splunkbase in case apps must be downloaded",
    )
    splunkbase_password: Union[str, None] = Field(
        default=None,
        title="The password for logging into Splunkbase in case apps must be downloaded",
    )
    apps: list[App] = Field(
        default=App.get_default_apps(),
        title="A list of all the apps to be installed on each container",
    )
    enable_integration_testing: bool = Field(
        default=False,
        title="Whether integration testing should be enabled, in addition to unit testing (requires a configured Splunk"
        " instance with ES installed)"
    )







    

    # Ensure that at least 1 of test_branch, commit_hash, and/or pr_number were passed.
    # Otherwise, what are we testing??
    # @root_validator(pre=False)
    def ensure_there_is_something_to_test(cls, values):
        if 'test_branch' not in values and 'commit_hash' not in values and'pr_number' not in values:
            if 'mode' in values and values['mode'] == DetectionTestingMode.changes:
                raise(ValueError(f"Under mode [{DetectionTestingMode.changes}], 'test_branch', 'commit_hash', and/or 'pr_number' must be defined so that we know what to test."))

        return values

    

    # presumably the post test behavior is validated by the enum?
    # presumably the mode is validated by the enum?

    @validator("detections_list", always=True)
    def validate_detections_list(cls, v, values):
        # A detections list can only be provided if the mode is selected
        # otherwise, we must throw an error

        # First check the mode
        if values["mode"] != DetectionTestingMode.selected:
            if v is not None:
                # We intentionally raise an error even if the list is an empty list
                raise (
                    ValueError(
                        f"For Detection Testing Mode '{values['mode']}', "
                        f"'detections_list' MUST be none.  Instead, it was a list containing {len(v)} detections."
                    )
                )
            return v

        # Mode is DetectionTestingMode.selected - verify the paths of all the detections
        all_errors = []
        if v == None:
            raise (
                ValueError(
                    f"mode is '{DetectionTestingMode.selected}', but detections_list was not provided."
                )
            )
        for detection in v:
            try:
                if not pathlib.Path(detection).exists():
                    all_errors.append(detection)
            except Exception as e:
                all_errors.append(
                    f"Unexpected error validating path '{detection}': {str(e)}"
                )
        if len(all_errors):
            joined_errors = "\n\t".join(all_errors)
            raise (
                ValueError(
                    f"Paths to the following detections in 'detections_list' "
                    f"were invalid: \n\t{joined_errors}"
                )
            )

        return v



  

    

    @validator("splunkbase_username")
    def validate_splunkbase_username(cls, v):
        return v

    @validator("splunkbase_password")
    def validate_splunkbase_password(cls, v, values):
        if values["splunkbase_username"] == None:
            return v
        elif (v == None and values["splunkbase_username"] != None) or (
            v != None and values["splunkbase_username"] == None
        ):
            raise (
                ValueError(
                    "splunkbase_username OR splunkbase_password "
                    "was provided, but not both.  You must provide"
                    " neither of these value or both, but not just "
                    "1 of them"
                )
            )

        else:
            return v

    @validator("apps",)
    def validate_apps(cls, v, values):
        

        app_errors = []

        # ensure that the splunkbase username and password are provided
        username = values["splunkbase_username"]
        password = values["splunkbase_password"]
        app_directory = LOCAL_APP_DIR
        try:
            os.makedirs(LOCAL_APP_DIR, exist_ok=True)
        except Exception as e:
            raise (
                Exception(f"Error: When trying to create {CONTAINER_APP_DIR}: {str(e)}")
            )

        for app in v:
            if app.environment_path != ENVIRONMENT_PATH_NOT_SET:
                #Avoid re-configuring the apps that have already been configured.
                continue

            try:
                app.configure_app_source_for_container(
                    username, password, app_directory, CONTAINER_APP_DIR
                )
            except Exception as e:
                error_string = f"Unable to prepare app '{app.title}': {str(e)}"
                app_errors.append(error_string)

        if len(app_errors) != 0:
            error_string = "\n\t".join(app_errors)
            raise (ValueError(f"Error preparing apps to install:\n\t{error_string}"))

        return v

    