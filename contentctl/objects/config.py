from __future__ import annotations
from pydantic import BaseModel, validator, Field, field_validator, field_serializer, ConfigDict, SecretStr, DirectoryPath

from datetime import datetime
from typing import Optional,Any,Dict
import semantic_version
import string
import random
from enum import StrEnum
import pathlib
#from contentctl.objects.test_config import TestConfig


# PASSWORD = ''.join([random.choice(string.ascii_letters + string.digits) for i in range(16)])

# class ConfigGlobal(BaseModel):
#     log_path: str
#     log_level: str


class ConfigScheduling(BaseModel):
    cron_schedule: str
    earliest_time: str
    latest_time: str
    schedule_window: str


class ConfigNotable(BaseModel):
    rule_description: str
    rule_title: str
    nes_fields: list


class ConfigEmail(BaseModel):
    subject: str
    to: str
    message: str


class ConfigSlack(BaseModel):
    channel: str
    message: str


class ConfigPhantom(BaseModel):
    cam_workers: str
    label: str
    phantom_server: str
    sensitivity: str
    severity: str


class ConfigRba(BaseModel):
    enabled: str


class ConfigDetectionConfiguration(BaseModel):
    scheduling: ConfigScheduling = ConfigScheduling(cron_schedule="0 * * * *", earliest_time="-70m@m", latest_time="-10m@m", schedule_window="auto")
    notable: ConfigNotable = ConfigNotable(rule_description="%description%", rule_title="%name%", nes_fields=["user", "dest", "src"])
    email: Optional[ConfigEmail] = None
    slack: Optional[ConfigSlack] = None
    phantom: Optional[ConfigPhantom] = None
    rba: Optional[ConfigRba] = None


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



class Config_App(BaseModel):
    # Fields required for app.conf based on
    # https://docs.splunk.com/Documentation/Splunk/9.0.4/Admin/Appconf
    title: str = Field(default="ContentPack",description="Internal name used by your app.  No spaces or special characters.")
    prefix: str = Field(default="ContentPack",description="A short prefix to easily identify all your content.")
    build: int = Field(default=int(datetime.utcnow().strftime("%Y%m%d%H%M%S")),
                       description="Build number for your app.  This will always be a number that corresponds to the time of the build in the format YYYYMMDDHHMMSS")
    version: str = Field(default="0.0.1",description="The version of your Content Pack.  This must follow semantic versioning guidelines.")
    uid: int = Field(ge=20000, lt=100000, default_factory=lambda:random.randint(20000,100000))
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
    appid: str = Field(default="ContentPack",description="Internal name used by your app.  No spaces or special characters.")
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
    


class Config_Base(BaseModel):
    model_config = ConfigDict(use_enum_values=True,validate_default=False, arbitrary_types_allowed=True)
    path: DirectoryPath = Field(default=DirectoryPath("."), description="The root of your app.")
    app:Config_App = Field(default_factory=Config_App)
    
    @field_serializer('path',when_used='always')
    def serialize_path(path: DirectoryPath)->str:
        return str(path)

class init(Config_Base):
    pass


class validate(Config_Base):
    enrichments: bool = Field(default=False, description="Enable MITRE, APP, and CVE Enrichments.  "\
                                                         "This is useful when outputting a release build "\
                                                         "and validating these values, but should otherwise "\
                                                         "be avoided for performance reasons.")
    build_app: bool = Field(default=True, description="Should an app be built and output in the {build_path}?")
    build_api: bool = Field(default=False, description="Should api objects be built and output in the {build_path}?")
    build_ssa: bool = Field(default=False, description="Should ssa objects be built and output in the {build_path}?")


class build(validate):
    build_path: DirectoryPath = Field(default=pathlib.Path("dist"), title="Target path for all build outputs")
    splunk_api_username: Optional[str] = Field(default=None,description="Splunk API username used for running appinspect.")
    splunk_api_password: Optional[str] = Field(default=None, exclude=True, description="Splunk API password used for running appinspect.")

    
    @field_validator('build_path',mode='before')
    @classmethod
    def ensure_build_path(cls, v:DirectoryPath):
        '''
        If the build path does not exist, then create it.
        If the build path is actually a file, then raise a descriptive
        exception.
        '''
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


#class Config_Test(BaseModel):
#    pass

class NewContentType(StrEnum):
    DETECTION = "detection"
    STORY = "story"


class new(BaseModel):
    type: NewContentType


class StackType(StrEnum):
    CLASSIC = "classic"
    VICTORIA = "victoria"


class deploy_acs(build):
    #ignore linter error
    splunk_cloud_jwt_token: str = Field(exclude=True, description="Splunk JWT used for performing ACS operations on a Splunk Cloud Instance")
    splunk_cloud_stack: str = Field(description="The name of your Splunk Cloud Stack")
    stack_type: StackType = Field(description="The type of your Splunk Cloud Stack")

    # Note that while these are a redefinition of fields with the same name in Config_Build object,
    # they are now REQUIRED instead of optional
    splunk_api_username: str = Field(description="Splunk API username used for running appinspect.")
    splunk_api_password: str = Field(exclude=True, description="Splunk API password used for running appinspect.")


    


class deploy_rest(build):
    #ignore linter error
    password: str = Field(description="Password for your Splunk Environment")

    api_port: int = Field(default=8089, description="API Port for your Splunk Environment")
    username: str = Field(default="admin", description="Username for your splunk environment")
    

    #This will overwrite existing content without promprting for confirmation
    overwrite_existing_content:bool = Field(default=True, description="Overwrite existing macros and savedsearches in your enviornment")



# class Config(BaseModel, extra="forbid"):
#     deployments: Deployments = Deployments()
#     build: Config_App = Config_App()
#     build_ssa: bool = False
#     build_api: bool = False
#     enrichments: ConfigEnrichments = ConfigEnrichments()
#     test: Optional[TestConfig] = None 
    


