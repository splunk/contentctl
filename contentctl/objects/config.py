from __future__ import annotations
from pydantic import (
    BaseModel, validator, Field, field_validator, 
    field_serializer, ConfigDict, SecretStr, DirectoryPath,
    PositiveInt, FilePath, HttpUrl, computed_field
)

from datetime import datetime
from typing import Optional,Any,Dict,Annotated,List,Union
import semantic_version
import random
from enum import StrEnum, auto
import pathlib
from contentctl.helper.utils import Utils
from urllib.parse import urlparse
from abc import ABC, abstractmethod
#from contentctl.objects.test_config import TestConfig


# PASSWORD = ''.join([random.choice(string.ascii_letters + string.digits) for i in range(16)])

# class ConfigGlobal(BaseModel):
#     log_path: str
#     log_level: str





# class ConfigAlertAction(BaseModel):
#     notable: ConfigNotable




# class ConfigDeploy(BaseModel):
#     description: str = "Description for this deployment target"
#     server: str = "127.0.0.1"

# CREDENTIAL_MISSING = "PROVIDE_CREDENTIALS_VIA_CMD_LINE_ARGUMENT"
# class ConfigDeployACS(ConfigDeploy):
#     token: str = CREDENTIAL_MISSING
    


    

# class Deployments(BaseModel):
#     acs_deployments: list[ConfigDeployACS] = []
#     rest_api_deployments: list[ConfigDeployRestAPI] = [ConfigDeployRestAPI()]

SPLUNKBASE_URL = "https://splunkbase.splunk.com/app/{uid}/release/{version}/download"

class App_Base(BaseModel,ABC):
    model_config = ConfigDict(use_enum_values=True,validate_default=True, arbitrary_types_allowed=True)
    uid: int = Field(ge=2, lt=100000, default_factory=lambda:random.randint(20000,100000))
    title: str = Field(default="Content Pack",description="Human-readable name used by the app. This can have special characters.")
    appid: Annotated[str, Field(pattern="^[a-zA-Z0-9_-]+$")]= Field(default="ContentPack",description="Internal name used by your app. "
                                                                    "It may ONLY have characters, numbers, and underscores. No other characters are allowed.")
    version: str = Field(default="0.0.1",description="The version of your Content Pack.  This must follow semantic versioning guidelines.")
    
    
   
    def getSplunkbasePath(self)->HttpUrl:
        return HttpUrl(SPLUNKBASE_URL.format(uid=self.uid, release=self.version))

    @abstractmethod
    def getApp(self, target_directory:pathlib.Path, config:test)->str:
        ...

class TestApp(App_Base):
    model_config = ConfigDict(use_enum_values=True,validate_default=True, arbitrary_types_allowed=True)
    hardcoded_path: Optional[Union[FilePath,HttpUrl]] = Field(description="This may be a relative or absolute link to a file OR an HTTP URL linking to your app.")
    def getApp(self, target_directory:pathlib.Path, config:test)->str:
        if config.splunk_api_password is not None and config.splunk_api_username is not None:
            destination = self.getSplunkbasePath()
        
        elif isinstance(self.hardcoded_path, FilePath):
            destination = config.getAppDir() / self.hardcoded_path.name
            Utils.copy_local_file(str(self.hardcoded_path), 
                                  str(destination), 
                                  verbose_print=True)

        elif isinstance(self.hardcoded_path,HttpUrl):
            file_url_string = str(self.hardcoded_path)
            server_path = pathlib.Path(urlparse(file_url_string).path)
            destination = config.getAppDir() / server_path.name
            Utils.download_file_from_http(file_url_string, str(destination))
        else:
            raise Exception(f"Unknown path for app '{self.title}'")
        
        return str(destination)


class CustomApp(App_Base):
    model_config = ConfigDict(use_enum_values=True,validate_default=True, arbitrary_types_allowed=True)
    # Fields required for app.conf based on
    # https://docs.splunk.com/Documentation/Splunk/9.0.4/Admin/Appconf
    prefix: str = Field(default="ContentPack",description="A short prefix to easily identify all your content.")
    build: int = Field(exclude=True, default=int(datetime.utcnow().strftime("%Y%m%d%H%M%S")),
                       description="Build number for your app.  This will always be a number that corresponds to the time of the build in the format YYYYMMDDHHMMSS")
    # id has many restrictions:
    # * Omit this setting for apps that are for internal use only and not intended
    # for upload to Splunkbase.
    # * id is required for all new apps that you upload to Splunkbase. Future versions of
    # Splunk Enterprise will use appid to correlate locally-installed apps and the
    # same app on Splunkbase (e.g. to notify users about app updates).
    # * id must be the same as the folder name in which your app lives in
    # $SPLUNK_HOME/etc/apps.
    # * id must adhere to these cross-platform folder name restrictions:
    # * must contain only letters, numbers, "." (dot), and "_" (underscore)
    # characters.
    # * must not end with a dot character.
    # * must not be any of the following names: CON, PRN, AUX, NUL,
    #   COM1, COM2, COM3, COM4, COM5, COM6, COM7, COM8, COM9,
    #   LPT1, LPT2, LPT3, LPT4, LPT5, LPT6, LPT7, LPT8, LPT9
    
    label: str = Field(default="Custom Splunk Content Pack",description="This is the app name that shows in the launcher.")
    author_name: str = Field(default="author name",description="Name of the Content Pack Author.")
    author_email: str = Field(default="author@contactemailaddress.com",description="Contact email for the Content Pack Author")
    author_company: str = Field(default="author company",description="Name of the company who has developed the Content Pack")
    description: str = Field(default="description of app",description="Free text description of the Content Pack.")


    @validator('version', always=True)
    def validate_version(cls, v, values):
        try:
            _ = semantic_version.Version(v)
        except Exception as e:
            raise(ValueError(f"The specified version does not follow the semantic versioning spec (https://semver.org/). {str(e)}"))
        return v
    
    #Build will ALWAYS be the current utc timestamp
    @validator('build', always=True)
    def validate_build(cls, v, values):
        return int(datetime.utcnow().strftime("%Y%m%d%H%M%S"))
    
    def getApp(self, target_directory:pathlib.Path, config:test)->str:
        destination = config.getAppDir() / (config.getPackageFilePath(include_version=True).name)
        Utils.copy_local_file(str(config.getPackageFilePath(include_version=True)), 
                              str(destination), 
                              verbose_print=True)
        return str(destination)


class Config_Base(BaseModel):
    model_config = ConfigDict(use_enum_values=True,validate_default=True, arbitrary_types_allowed=True)

    path: DirectoryPath = Field(default=DirectoryPath("."), description="The root of your app.")
    app:CustomApp = Field(default_factory=CustomApp)
    
    @field_serializer('path',when_used='always')
    def serialize_path(path: DirectoryPath)->str:
        return str(path)

class init(Config_Base):
    pass


class validate(Config_Base):
    model_config = ConfigDict(use_enum_values=True,validate_default=True, arbitrary_types_allowed=True)
    enrichments: bool = Field(default=False, description="Enable MITRE, APP, and CVE Enrichments.  "\
                                                         "This is useful when outputting a release build "\
                                                         "and validating these values, but should otherwise "\
                                                         "be avoided for performance reasons.")
    build_app: bool = Field(default=True, description="Should an app be built and output in the {build_path}?")
    build_api: bool = Field(default=False, description="Should api objects be built and output in the {build_path}?")
    build_ssa: bool = Field(default=False, description="Should ssa objects be built and output in the {build_path}?")


class build(validate):
    model_config = ConfigDict(use_enum_values=True,validate_default=True, arbitrary_types_allowed=True)
    build_path: DirectoryPath = Field(default=DirectoryPath("dist/"), title="Target path for all build outputs")

    @field_serializer('build_path',when_used='always')
    def serialize_build_path(path: DirectoryPath)->str:
        return str(path)

    @field_validator('build_path',mode='before')
    @classmethod
    def ensure_build_path(cls, v:Union[str,DirectoryPath]):
        '''
        If the build path does not exist, then create it.
        If the build path is actually a file, then raise a descriptive
        exception.
        '''
        if isinstance(v,str):
            v = pathlib.Path(v)
        if v.is_dir():
            return v
        elif v.is_file():
            raise ValueError(f"Build path {v} must be a directory, but instead it is a file")
        elif not v.exists():
            v.mkdir(parents=True)
        return v
    
    def getBuildDir(self)->pathlib.Path:
        return self.path / self.build_path

    def getPackageDirectoryPath(self)->pathlib.Path:
        return self.getBuildDir() /  f"{self.app.appid}"
        

    def getPackageFilePath(self, include_version:bool=False)->pathlib.Path:
        if include_version:
            return self.getBuildDir() / f"{self.app.appid}-{self.app.version}.tar.gz"
        else:
            return self.getBuildDir() / f"{self.app.appid}-latest.tar.gz"
    
    def getSSAPath(self)->pathlib.Path:
        return self.getBuildDir() / "ssa"

    def getAPIPath(self)->pathlib.Path:
        return self.getBuildDir() / "api"

    def getAppTemplatePath(self)->pathlib.Path:
        return self.path/"app_template"


class StackType(StrEnum):
    classic = auto()
    victoria = auto()

class inspect(build):
    splunk_api_username: str = Field(description="Splunk API username used for running appinspect.")
    splunk_api_password: str = Field(exclude=True, description="Splunk API password used for running appinspect.")
    stack_type: StackType = Field(description="The type of your Splunk Cloud Stack")

class NewContentType(StrEnum):
    detection = auto()
    story = auto()




class new(Config_Base):
    type: NewContentType = Field(default=NewContentType.detection, description="Specify the type of content you would like to create.")





class deploy_acs(inspect):
    model_config = ConfigDict(use_enum_values=True,validate_default=False, arbitrary_types_allowed=True)
    #ignore linter error
    splunk_cloud_jwt_token: str = Field(exclude=True, description="Splunk JWT used for performing ACS operations on a Splunk Cloud Instance")
    splunk_cloud_stack: str = Field(description="The name of your Splunk Cloud Stack")

    # Note that while these are a redefinition of fields with the same name in Config_Build object,
    # they are now REQUIRED instead of optional
    splunk_api_username: str = Field(description="Splunk API username used for running appinspect.")
    splunk_api_password: str = Field(exclude=True, description="Splunk API password used for running appinspect.")


    
class Infrastructure(BaseModel):
    model_config = ConfigDict(use_enum_values=True,validate_default=True, arbitrary_types_allowed=True)
    splunk_app_username:str = Field(default="admin", description="Username for logging in to your Splunk Server")
    splunk_app_password:str = Field(exclude=True, default="password", description="Password for logging in to your Splunk Server.")
    instance_address:str = Field(..., description="Address of your splunk server.")
    hec_port: int = Field(default=8088, gt=1, lt=65536, title="HTTP Event Collector Port")
    web_ui_port: int = Field(default=8000, gt=1, lt=65536, title="Web UI Port")
    api_port: int = Field(default=8089, gt=1, lt=65536, title="REST API Port")


class deploy_rest(build):
    model_config = ConfigDict(use_enum_values=True,validate_default=True, arbitrary_types_allowed=True)
    
    target:Infrastructure = Infrastructure(instance_address="localhost")
    #This will overwrite existing content without promprting for confirmation
    overwrite_existing_content:bool = Field(default=True, description="Overwrite existing macros and savedsearches in your enviornment")


    
class Container(Infrastructure):
    model_config = ConfigDict(use_enum_values=True,validate_default=True, arbitrary_types_allowed=True)
    instance_address:str = Field(default="localhost", description="Address of your splunk server.")
    full_image_path:str = Field(default="https://registry.hub.docker.com/splunk/splunk:latest",
                                title="Full path to the container image to be used")

class ContainerSettings(BaseModel):
    model_config = ConfigDict(use_enum_values=True,validate_default=True, arbitrary_types_allowed=True)
    leave_running: bool = Field(default=True, description="Leave container running after it is first "
                                "set up to speed up subsequent test runs.")
    num_containers: PositiveInt = Field(default=1, description="Number of containers to start in parallel. "
                                        "Please note that each container is quite expensive to run.  It is not "
                                        "recommended to run more than 4 containers unless you have a very "
                                        "well-resourced environment.")

class All(BaseModel):
    #Doesn't need any extra logic
    pass

class Changes(BaseModel):
    model_config = ConfigDict(use_enum_values=True,validate_default=True, arbitrary_types_allowed=True)
    target_branch:str = Field(default="main",description="The target branch to diff against. Note that this includes uncommitted changes in the working directory as well.")


class Selected(BaseModel):
    model_config = ConfigDict(use_enum_values=True,validate_default=True, arbitrary_types_allowed=True)
    files:List[FilePath] = Field(...,description="List of detection files to test, separated by spaces.")



class test(build):
    model_config = ConfigDict(use_enum_values=True,validate_default=True, arbitrary_types_allowed=True)
    test_instance:Container = Container()
    container_settings:ContainerSettings = ContainerSettings()
    mode:Union[All, Changes, Selected] = Changes()

    def getAppDir(self)->pathlib.Path:
        return self.path / "apps"

class test_servers(build):
    model_config = ConfigDict(use_enum_values=True,validate_default=True, arbitrary_types_allowed=True)
    servers:List[Infrastructure] = Field([Infrastructure(instance_address="splunkServerAddress.com")],description="Test against one or more preconfigured servers.")
    mode:Union[All, Changes, Selected] = Field(...,description="Test All content in the app, Selected files, or Automatically determine the changes between two branches (includes uncommitted changes in your working directory).")

