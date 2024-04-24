from __future__ import annotations
from pydantic import (
    BaseModel, Field, field_validator, 
    field_serializer, ConfigDict, DirectoryPath,
    PositiveInt, FilePath, HttpUrl, AnyUrl, computed_field, model_validator
)


from datetime import datetime, UTC
from typing import Optional,Any,Dict,Annotated,List,Union, Self
import semantic_version
import random
from enum import StrEnum, auto
import pathlib
from contentctl.helper.utils import Utils
from urllib.parse import urlparse
from abc import ABC, abstractmethod
from contentctl.objects.enums import PostTestBehavior
from contentctl.input.yml_reader import YmlReader



# from contentctl.objects.test_config import TestConfig


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
    uid: Optional[int] = Field(default=None)
    title: str = Field(description="Human-readable name used by the app. This can have special characters.")
    appid: Optional[Annotated[str, Field(pattern="^[a-zA-Z0-9_-]+$")]]= Field(default=None,description="Internal name used by your app. "
                                                                    "It may ONLY have characters, numbers, and underscores. No other characters are allowed.")
    version: str = Field(description="The version of your Content Pack.  This must follow semantic versioning guidelines.")
    description: Optional[str] = Field(default="description of app",description="Free text description of the Content Pack.")
    
   
    def getSplunkbasePath(self)->HttpUrl:
        return HttpUrl(SPLUNKBASE_URL.format(uid=self.uid, release=self.version))

    @abstractmethod
    def getApp(self, config:test, stage_file:bool=False)->str:
        ...

    def ensureAppPathExists(self, config:test, stage_file:bool=False):
        if stage_file:
            if not config.getLocalAppDir().exists():
                config.getLocalAppDir().mkdir(parents=True)

class TestApp(App_Base):
    model_config = ConfigDict(use_enum_values=True,validate_default=True, arbitrary_types_allowed=True)
    hardcoded_path: Optional[Union[FilePath,HttpUrl]] = Field(default=None, description="This may be a relative or absolute link to a file OR an HTTP URL linking to your app.")
    
    def getApp(self, config:test,stage_file:bool=False)->str:
        #If the apps directory does not exist, then create it
        self.ensureAppPathExists(config,stage_file)

        if config.splunk_api_password is not None and config.splunk_api_username is not None:
            if self.version is not None and self.uid is not None:
               return str(self.getSplunkbasePath())
            if self.version is None or self.uid is None:
                print(f"Not downloading {self.title} from Splunkbase since uid[{self.uid}] AND version[{self.version}] MUST be defined") 
            
        
        elif isinstance(self.hardcoded_path, pathlib.Path):
            destination = config.getLocalAppDir() / self.hardcoded_path.name
            if stage_file:
                Utils.copy_local_file(str(self.hardcoded_path), 
                                        str(destination), 
                                        verbose_print=True)

        elif isinstance(self.hardcoded_path, AnyUrl):
            file_url_string = str(self.hardcoded_path)
            server_path = pathlib.Path(urlparse(file_url_string).path)
            destination = config.getLocalAppDir() / server_path.name
            if stage_file:
                Utils.download_file_from_http(file_url_string, str(destination))
        else:
            raise Exception(f"Unknown path for app '{self.title}'")
        
        return str(destination)

class CustomApp(App_Base):
    model_config = ConfigDict(use_enum_values=True,validate_default=True, arbitrary_types_allowed=True)
    # Fields required for app.conf based on
    # https://docs.splunk.com/Documentation/Splunk/9.0.4/Admin/Appconf
    uid: int = Field(ge=2, lt=100000, default_factory=lambda:random.randint(20000,100000))
    title: str = Field(default="Content Pack",description="Human-readable name used by the app. This can have special characters.")
    appid: Annotated[str, Field(pattern="^[a-zA-Z0-9_-]+$")]= Field(default="ContentPack",description="Internal name used by your app. "
                                                                    "It may ONLY have characters, numbers, and underscores. No other characters are allowed.")
    version: str = Field(default="0.0.1",description="The version of your Content Pack.  This must follow semantic versioning guidelines.", validate_default=True)

    prefix: str = Field(default="ContentPack",description="A short prefix to easily identify all your content.")
    build: int = Field(exclude=True, default=int(datetime.now(UTC).strftime("%Y%m%d%H%M%S")), validate_default=True,
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


    @field_validator('version')
    def validate_version(cls, v, values):
        try:
            _ = semantic_version.Version(v)
        except Exception as e:
            raise(ValueError(f"The specified version does not follow the semantic versioning spec (https://semver.org/). {str(e)}"))
        return v
    
    #Build will ALWAYS be the current utc timestamp
    @field_validator('build')
    def validate_build(cls, v, values):
        return int(datetime.utcnow().strftime("%Y%m%d%H%M%S"))
    
    def getApp(self, config:test, stage_file=True)->str:
        self.ensureAppPathExists(config,stage_file)
        
        destination = config.getLocalAppDir() / (config.getPackageFilePath(include_version=True).name)
        if stage_file:
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


class Infrastructure(BaseModel):
    model_config = ConfigDict(use_enum_values=True,validate_default=True, arbitrary_types_allowed=True)
    splunk_app_username:str = Field(default="admin", description="Username for logging in to your Splunk Server")
    splunk_app_password:str = Field(exclude=True, default="password", description="Password for logging in to your Splunk Server.")
    instance_address:str = Field(..., description="Address of your splunk server.")
    hec_port: int = Field(default=8088, gt=1, lt=65536, title="HTTP Event Collector Port")
    web_ui_port: int = Field(default=8000, gt=1, lt=65536, title="Web UI Port")
    api_port: int = Field(default=8089, gt=1, lt=65536, title="REST API Port")
    instance_name: str = Field(...)


class deploy_rest(build):
    model_config = ConfigDict(use_enum_values=True,validate_default=True, arbitrary_types_allowed=True)
    
    target:Infrastructure = Infrastructure(instance_name="splunk_target_host", instance_address="localhost")
    #This will overwrite existing content without promprting for confirmation
    overwrite_existing_content:bool = Field(default=True, description="Overwrite existing macros and savedsearches in your enviornment")


class Container(Infrastructure):
    model_config = ConfigDict(use_enum_values=True,validate_default=True, arbitrary_types_allowed=True)
    instance_address:str = Field(default="localhost", description="Address of your splunk server.")


class ContainerSettings(BaseModel):
    model_config = ConfigDict(use_enum_values=True,validate_default=True, arbitrary_types_allowed=True)
    leave_running: bool = Field(default=True, description="Leave container running after it is first "
                                "set up to speed up subsequent test runs.")
    num_containers: PositiveInt = Field(default=1, description="Number of containers to start in parallel. "
                                        "Please note that each container is quite expensive to run.  It is not "
                                        "recommended to run more than 4 containers unless you have a very "
                                        "well-resourced environment.")
    full_image_path:str = Field(default="registry.hub.docker.com/splunk/splunk:latest",        
                                title="Full path to the container image to be used")
    
    def getContainers(self)->List[Container]:
        containers = []
        for i in range(self.num_containers):
            containers.append(Container(instance_name="contentctl_{}".format(i),
                                        web_ui_port=8000+i, hec_port=8088+(i*2), api_port=8089+(i*2)))

        return containers


class All(BaseModel):
    #Doesn't need any extra logic
    pass

class Changes(BaseModel):
    model_config = ConfigDict(use_enum_values=True,validate_default=True, arbitrary_types_allowed=True)
    target_branch:str = Field(default="main",description="The target branch to diff against. Note that this includes uncommitted changes in the working directory as well.")


class Selected(BaseModel):
    model_config = ConfigDict(use_enum_values=True,validate_default=True, arbitrary_types_allowed=True)
    files:List[FilePath] = Field(...,description="List of detection files to test, separated by spaces.")


class test_common(build):
    mode:Union[All, Changes, Selected] = Changes()
    post_test_behavior: PostTestBehavior = Field(default=PostTestBehavior.pause_on_failure, description="")
    test_instances:List[Infrastructure] = Field(...)
    enable_integration_testing: bool = Field(default=False, description="Enable integration testing, which REQUIRES Splunk Enterprise Security "
                                             "to be installed on the server. This checks for a number of different things including generation "
                                             "of appropriate notables and messages. Please note that this will increase testing time "
                                             "considerably (by approximately 2-3 minutes per detection).")

    def getModeName(self)->str:
        if isinstance(self.mode, All):
            return "All"
        elif isinstance(self.mode, Changes):
            return "Changes"
        else:
            return "Selected"



DEFAULT_APPS:List[TestApp] = [
        TestApp(
            uid=1621,
            appid="Splunk_SA_CIM",
            title="Splunk Common Information Model (CIM)",
            version="5.2.0",
            hardcoded_path=HttpUrl(
                "https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/Latest/splunk-common-information-model-cim_520.tgz"
            ),
         ),
        TestApp(
            uid=6553,
            appid="Splunk_TA_okta_identity_cloud",
            title="Splunk Add-on for Okta Identity Cloud",
            version="2.1.0",
            hardcoded_path=HttpUrl(
                "https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/Latest/splunk-add-on-for-okta-identity-cloud_210.tgz"
            ),
        ),
        TestApp(
            uid=6176,
            appid="Splunk_TA_linux_sysmon",
            title="Add-on for Linux Sysmon",
            version="1.0.4",
            hardcoded_path=HttpUrl(
                "https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/Latest/add-on-for-linux-sysmon_104.tgz"
            ),
        ),
        TestApp(
            appid="Splunk_FIX_XMLWINEVENTLOG_HEC_PARSING",
            title="Splunk Fix XmlWinEventLog HEC Parsing",
            version="0.1",
            description="This TA is required for replaying Windows Data into the Test Environment. The Default TA does not include logic for properly splitting multiple log events in a single file.  In production environments, this logic is applied by the Universal Forwarder.",
            hardcoded_path=HttpUrl(
                "https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/Latest/Splunk_TA_fix_windows.tgz"
            ),
        ),
        TestApp(
            uid=742,
            appid="SPLUNK_ADD_ON_FOR_MICROSOFT_WINDOWS",
            title="Splunk Add-on for Microsoft Windows",
            version="8.8.0",
            hardcoded_path=HttpUrl(
                "https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/Latest/splunk-add-on-for-microsoft-windows_880.tgz"
            ),
        ),
        TestApp(
            uid=5709,
            appid="Splunk_TA_microsoft_sysmon",
            title="Splunk Add-on for Sysmon",
            version="4.0.0",
            hardcoded_path=HttpUrl(
                "https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/Latest/splunk-add-on-for-sysmon_400.tgz"
            ),
        ),
        TestApp(
            uid=833,
            appid="Splunk_TA_nix",
            title="Splunk Add-on for Unix and Linux",
            version="9.0.0",
            hardcoded_path=HttpUrl(
                "https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/Latest/splunk-add-on-for-unix-and-linux_900.tgz"
            ),
        ),
        TestApp(
            uid=5579,
            appid="Splunk_TA_CrowdStrike_FDR",
            title="Splunk Add-on for CrowdStrike FDR",
            version="1.5.0",
            hardcoded_path=HttpUrl(
                "https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/Latest/splunk-add-on-for-crowdstrike-fdr_150.tgz"
            ),
        ),
        TestApp(
            uid=3185,
            appid="SPLUNK_TA_FOR_IIS",
            title="Splunk Add-on for Microsoft IIS",
            version="1.3.0",
            hardcoded_path=HttpUrl(
                "https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/Latest/splunk-add-on-for-microsoft-iis_130.tgz"
            ),
        ),
        TestApp(
            uid=4242,
            appid="SPLUNK_TA_FOR_SURICATA",
            title="TA for Suricata",
            version="2.3.4",
            hardcoded_path=HttpUrl(
                "https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/Latest/ta-for-suricata_234.tgz"
            ),
        ),
        TestApp(
            uid=5466,
            appid="SPLUNK_TA_FOR_ZEEK",
            title="TA for Zeek",
            version="1.0.6",
            hardcoded_path=HttpUrl(
                "https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/Latest/ta-for-zeek_106.tgz"
            ),
        ),
        TestApp(
            uid=3258,
            appid="SPLUNK_ADD_ON_FOR_NGINX",
            title="Splunk Add-on for NGINX",
            version="3.2.2",
            hardcoded_path=HttpUrl(
                "https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/Latest/splunk-add-on-for-nginx_322.tgz"
            ),
        ),
        TestApp(
            uid=5238,
            appid="SPLUNK_ADD_ON_FOR_STREAM_FORWARDERS",
            title="Splunk Add-on for Stream Forwarders",
            version="8.1.1",
            hardcoded_path=HttpUrl(
                "https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/Latest/splunk-add-on-for-stream-forwarders_811.tgz"
            ),
        ),
        TestApp(
            uid=5234,
            appid="SPLUNK_ADD_ON_FOR_STREAM_WIRE_DATA",
            title="Splunk Add-on for Stream Wire Data",
            version="8.1.1",
            hardcoded_path=HttpUrl(
                "https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/Latest/splunk-add-on-for-stream-wire-data_811.tgz"
            ),
        ),
        TestApp(
            uid=2757,
            appid="PALO_ALTO_NETWORKS_ADD_ON_FOR_SPLUNK",
            title="Palo Alto Networks Add-on for Splunk",
            version="8.1.1",
            hardcoded_path=HttpUrl(
                "https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/Latest/palo-alto-networks-add-on-for-splunk_811.tgz"
            ),
        ),
        TestApp(
            uid=3865,
            appid="Zscaler_CIM",
            title="Zscaler Technical Add-On for Splunk",
            version="4.0.3",
            hardcoded_path=HttpUrl(
                "https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/Latest/zscaler-technical-add-on-for-splunk_403.tgz"
            ),
        ),
        TestApp(
            uid=3719,
            appid="SPLUNK_ADD_ON_FOR_AMAZON_KINESIS_FIREHOSE",
            title="Splunk Add-on for Amazon Kinesis Firehose",
            version="1.3.2",
            hardcoded_path=HttpUrl(
                "https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/Latest/splunk-add-on-for-amazon-kinesis-firehose_132.tgz"
            ),
        ),
        TestApp(
            uid=1876,
            appid="Splunk_TA_aws",
            title="Splunk Add-on for AWS",
            version="7.5.0",
            hardcoded_path=HttpUrl(
                "https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/Latest/splunk-add-on-for-amazon-web-services-aws_750.tgz"
            ),
        ),
        TestApp(
            uid=3088,
            appid="SPLUNK_ADD_ON_FOR_GOOGLE_CLOUD_PLATFORM",
            title="Splunk Add-on for Google Cloud Platform",
            version="4.4.0",
            hardcoded_path=HttpUrl(
                "https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/Latest/splunk-add-on-for-google-cloud-platform_440.tgz"
            ),
        ),
        TestApp(
            uid=5556,
            appid="SPLUNK_ADD_ON_FOR_GOOGLE_WORKSPACE",
            title="Splunk Add-on for Google Workspace",
            version="2.6.3",
            hardcoded_path=HttpUrl(
                "https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/Latest/splunk-add-on-for-google-workspace_263.tgz"
            ),
        ),
        TestApp(
            uid=3110,
            appid="SPLUNK_TA_MICROSOFT_CLOUD_SERVICES",
            title="Splunk Add-on for Microsoft Cloud Services",
            version="5.2.2",
            hardcoded_path=HttpUrl(
                "https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/Latest/splunk-add-on-for-microsoft-cloud-services_522.tgz"
            ),
        ),
        TestApp(
            uid=4055,
            appid="SPLUNK_ADD_ON_FOR_MICROSOFT_OFFICE_365",
            title="Splunk Add-on for Microsoft Office 365",
            version="4.5.1",
            hardcoded_path=HttpUrl(
                "https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/Latest/splunk-add-on-for-microsoft-office-365_451.tgz"
            ),
        ),
        TestApp(
            uid=2890,
            appid="SPLUNK_MACHINE_LEARNING_TOOLKIT",
            title="Splunk Machine Learning Toolkit",
            version="5.4.1",
            hardcoded_path=HttpUrl(
                "https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/Latest/splunk-machine-learning-toolkit_541.tgz"
            ),
        ),
        TestApp(
            uid=2734,
            appid="URL_TOOLBOX",
            title="URL Toolbox",
            version="1.9.2",
            hardcoded_path=HttpUrl(
                "https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/Latest/url-toolbox_192.tgz"
            ),
        ),
    ]

class test(test_common):
    model_config = ConfigDict(use_enum_values=True,validate_default=True, arbitrary_types_allowed=True)
    container_settings:ContainerSettings = ContainerSettings()
    test_instances:List[Container] = Field(default=container_settings.getContainers(),validate_default=True)
    
    splunk_api_username: Optional[str] = Field(default=None, description="Splunk API username used for running appinspect or installating apps from Splunkbase")
    splunk_api_password: Optional[str] = Field(default=None, exclude=True, description="Splunk API password used for running appinspect or installaing apps from Splunkbase")
    #apps: List[TestApp] = Field(default=DEFAULT_APPS, exclude=True, description="List of apps to install in test environment")
    
    
    def getLocalAppDir(self)->pathlib.Path:
        return self.path / "apps"
    
    def getContainerAppDir(self)->pathlib.Path:
        return pathlib.Path("/tmp/apps")
    
    
    @model_validator(mode='after')
    def ensureAppsAreGood(self)->Self:
        """
        This function ensures that, after the rest of the configuration 
        has been validated, all of the apps are able to be correctly resolved.
        This includes apps that may be sourced from local files, HTTP files,
        and/or Splunkbase.  

        This is NOT a model_post_init function because it does perform some validation,
        even though it does not change the object

        Raises:
            Exception: There was a failure in parsing/validating all referenced apps

        Returns:
            Self: The test object. No modifications are made during this call.
        """        
        try:
            _ = self.getContainerEnvironmentString(stage_file=False, include_custom_app=False)
        except Exception as e:
            raise Exception(f"Error validating test apps: {str(e)}")
        return self

    @computed_field
    @property
    def apps(self)->List[TestApp]:        
        if not self.getAppFilePath().exists():
            return DEFAULT_APPS
        
        app_objects:List[App_Base] = []
        data:List[dict[str,Any]] = YmlReader.load_file(self.getAppFilePath())
        for app in data:
            try:
                t = TestApp.model_validate(app)
                app_objects.append(t)
            except Exception as e:
                raise Exception(f"Failed parsing the following dictionary into a test app with error(s) :{str(e)}:\n\n{app}")

        return app_objects
    
    def getContainerEnvironmentString(self,stage_file:bool=True, include_custom_app:bool=True)->str:
        apps:List[App_Base] = self.apps
        if include_custom_app:
            apps.append(self.app)

        paths = [app.getApp(self,stage_file=stage_file) for app in apps]

        container_paths = []
        for path in paths:
            if path.startswith(SPLUNKBASE_URL):
                container_paths.append(path)
            else:
                container_paths.append(str(self.getContainerAppDir()/pathlib.Path(path).name))
        
        return ','.join(container_paths)

    def getAppFilePath(self):
        return self.path / "apps.yml"



class test_servers(test_common):
    model_config = ConfigDict(use_enum_values=True,validate_default=True, arbitrary_types_allowed=True)
    test_instances:List[Infrastructure] = Field([Infrastructure(instance_name="splunk_target", instance_address="splunkServerAddress.com")],description="Test against one or more preconfigured servers.")
