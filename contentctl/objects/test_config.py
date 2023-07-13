# Needed for a staticmethod to be able to return an instance of the class it belongs to
from __future__ import annotations


import validators
import pathlib
import yaml
import os
from pydantic import BaseModel, validator, root_validator, Extra, Field
from dataclasses import dataclass
from typing import Union
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


class TestConfig(BaseModel, extra=Extra.forbid, validate_assignment=True):
    repo_path: str = Field(default=".", title="Path to the root of your app")
    repo_url: Union[str, None] = Field(
        default=None,
        title="HTTP(s) path to the repo for repo_path.  If this field is blank, it will be inferred from the repo",
    )
    # main_branch: Union[str,None] = Field(default=None, title="Main branch of the repo, if applicable.")
    # test_branch: Union[str,None] = Field(default=None, title="Branch of the repo to be tested, if applicable.")
    # commit_hash: Union[str,None] = Field(default=None, title="Commit hash of the repo state to be tested, if applicable")
    target_infrastructure: DetectionTestingTargetInfrastructure = Field(
        default=DetectionTestingTargetInfrastructure.container,
        title=f"Control where testing should be launched.  Choose one of {DetectionTestingTargetInfrastructure._member_names_}",
    )
    full_image_path: str = Field(
        default="registry.hub.docker.com/splunk/splunk:latest",
        title="Full path to the container image to be used",
    )
    container_name: str = Field(
        default="splunk_contentctl_%d",
        title="Template to be used for naming the Splunk Test Containers which will be created",
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
    num_containers: int = Field(
        default=1, title="Number of testing containers to start in parallel."
    )
    # pr_number: Union[int,None] = Field(default=None, title="The number of the PR to test")
    splunk_app_username: Union[str, None] = Field(
        default="admin", title="The name of the user for testing"
    )
    splunk_app_password: Union[str, None] = Field(
        default="password", title="Password for logging into Splunk Server"
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
    test_instance_address: str = Field(
        default="127.0.0.1",
        title="Domain name of IP address of Splunk server to be used for testing. Do NOT use a protocol, like http(s):// or 'localhost'",
    )

    hec_port: int = Field(default=8088, title="HTTP Event Collector Port")
    web_ui_port: int = Field(default=8000, title="Web UI Port")
    api_port: int = Field(default=8089, title="REST API Port")


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
        global PREVIOUSLY_ALLOCATED_PORTS
        if type(v) is not list:
            # Otherwise this throws error when we update a single field
            return v
        if len(set(v)) != len(v):
            raise (ValueError(f"Duplicate ports detected: [{v}]"))

        if PREVIOUSLY_ALLOCATED_PORTS.isdisjoint(v):
            PREVIOUSLY_ALLOCATED_PORTS = PREVIOUSLY_ALLOCATED_PORTS.union()
        else:
            raise (
                ValueError(
                    f"Duplicate ports detected: [{PREVIOUSLY_ALLOCATED_PORTS.intersection(v)}]"
                )
            )

        return v

    # Ensure that at least 1 of test_branch, commit_hash, and/or pr_number were passed.
    # Otherwise, what are we testing??
    # @root_validator(pre=False)
    # def ensure_there_is_something_to_test(cls, values):
    #     if 'test_branch' not in values and 'commit_hash' not in values and'pr_number' not in values:
    #         if 'mode' in values and values['mode'] == DetectionTestingMode.changes:
    #             raise(ValueError(f"Under mode [{DetectionTestingMode.changes}], 'test_branch', 'commit_hash', and/or 'pr_number' must be defined so that we know what to test."))

    #     return values

    # @validator('repo_path', always=True)
    # def validate_repo_path(cls,v):

    #     try:
    #         path = pathlib.Path(v)
    #     except Exception as e:
    #         raise(ValueError(f"Error, the provided path is is not a valid path: '{v}'"))

    #     try:
    #         r = git.Repo(path)
    #     except Exception as e:
    #         raise(ValueError(f"Error, the provided path is not a valid git repo: '{path}'"))

    #     try:

    #         if ALWAYS_PULL_REPO:
    #             r.remotes.origin.pull()
    #     except Exception as e:
    #         raise ValueError(f"Error pulling git repository {v}: {str(e)}")

    #     return v

    # @validator('repo_url', always=True)
    # def validate_repo_url(cls, v, values):
    #     Utils.check_required_fields('repo_url', values, ['repo_path'])

    #     #First try to get the value from the repo
    #     try:
    #         remote_url_from_repo = git.Repo(values['repo_path']).remotes.origin.url
    #     except Exception as e:
    #         raise(ValueError(f"Error reading remote_url from the repo located at {values['repo_path']}"))

    #     if v is not None and remote_url_from_repo != v:
    #         raise(ValueError(f"The url of the remote repo supplied in the config file {v} does not "\
    #                           f"match the value read from the repository at {values['repo_path']}, {remote_url_from_repo}"))

    #     if v is None:
    #         v = remote_url_from_repo

    #     #Ensure that the url is the proper format
    #     try:
    #         if bool(validators.url(v)) == False:
    #             raise(Exception)
    #     except:
    #         raise(ValueError(f"Error validating the repo_url. The url is not valid: {v}"))

    #     return v

    # @validator('main_branch', always=True)
    # def valid_main_branch(cls, v, values):
    #     Utils.check_required_fields('main_branch', values, ['repo_path', 'repo_url'])

    #     if v is None:
    #         print(f"main_branch is not supplied.  Inferring from '{values['repo_path']}'...",end='')

    #         main_branch = Utils.get_default_branch_name(values['repo_path'], values['repo_url'])
    #         print(f"main_branch name '{main_branch}' inferred'")
    #         #continue with the validation
    #         v = main_branch

    #     try:
    #         Utils.validate_git_branch_name(values['repo_path'],values['repo_url'], v)
    #     except Exception as e:
    #         raise ValueError(f"Error validating main_branch: {str(e)}")
    #     return v

    # @validator('test_branch', always=True)
    # def validate_test_branch(cls, v, values):
    #     Utils.check_required_fields('test_branch', values, ['repo_path', 'repo_url', 'main_branch'])
    #     if v is None:
    #         print(f"No test_branch provided, so we will default to using the main_branch '{values['main_branch']}'")
    #         return values['main_branch']
    #     try:
    #         Utils.validate_git_branch_name(values['repo_path'],values['repo_url'], v)
    #     except Exception as e:
    #         raise ValueError(f"Error validating test_branch: {str(e)}")
    #     return v

    # @validator('commit_hash', always=True)
    # def validate_commit_hash(cls, v, values):
    #     Utils.check_required_fields('commit_hash', values, ['repo_path', 'repo_url', 'test_branch'])

    #     try:
    #         #We can a hash with this function too
    #         Utils.validate_git_hash(values['repo_path'],values['repo_url'], v, values['test_branch'])
    #     except Exception as e:
    #         raise ValueError(f"Error validating commit_hash '{v}': {str(e)}")
    #     return v

    @validator("full_image_path", always=True)
    def validate_full_image_path(cls, v, values):
        if (
            values.get("target_infrastructure", None)
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

    # presumably the post test behavior is validated by the enum?
    # presumably the mode is validated by the enum?

    @validator("detections_list", always=True)
    def validate_detections_list(cls, v, values):

        Utils.check_required_fields("detections_list", values, ["mode", "repo_path"])
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
                full_path = os.path.join(values["repo_path"], detection)
                if not pathlib.Path(full_path).exists():
                    all_errors.append(full_path)
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

    @validator("num_containers", always=True)
    def validate_num_containers(cls, v):
        MAX_RECOMMENDED_CONTAINERS_BEFORE_WARNING = 2
        if v < 1:
            raise (
                ValueError(
                    f"Error validating num_containers. Test must be run with at least 1 container, not {v}"
                )
            )
        if v > MAX_RECOMMENDED_CONTAINERS_BEFORE_WARNING:
            print(
                f"You requested to run with [{v}] containers which may use a very large amount of resources "
                "as they all run in parallel.  The maximum suggested number of parallel containers is "
                f"[{MAX_RECOMMENDED_CONTAINERS_BEFORE_WARNING}].  We will do what you asked, but be warned!"
            )
        return v

    # @validator('pr_number', always=True)
    # def validate_pr_number(cls, v, values):
    #     Utils.check_required_fields('pr_number', values, ['repo_path', 'commit_hash'])

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

    @validator("splunk_app_password", always=True)
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

    @validator("splunkbase_username", always=True)
    def validate_splunkbase_username(cls, v):
        return v

    @validator("splunkbase_password", always=True)
    def validate_splunkbase_password(cls, v, values):
        Utils.check_required_fields("repo_url", values, ["splunkbase_username"])
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
        Utils.check_required_fields(
            "repo_url", values, ["splunkbase_username", "splunkbase_password"]
        )

        app_errors = []

        # ensure that the splunkbase username and password are provided
        username = values["splunkbase_username"]
        password = values["splunkbase_password"]
        app_directory = pathlib.Path(values["repo_path"]) / LOCAL_APP_DIR
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

    @validator("target_infrastructure", always=True)
    def validate_target_infrastructure(cls, v, values):
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

    @validator("test_instance_address", always=True)
    def validate_test_instance_address(cls, v, values):
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
                    f"Error, failed to validate test_instance_address '{v}': {str(e)}"
                )
            )
