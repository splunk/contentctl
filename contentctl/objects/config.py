from pydantic import BaseModel, validator, ValidationError, Field, Extra
import semantic_version
from datetime import datetime
from typing import Union
from contentctl.objects.test_config import TestConfig

import string
import random
PASSWORD = ''.join([random.choice(string.ascii_letters + string.digits) for i in range(16)])

class ConfigGlobal(BaseModel):
    log_path: str
    log_level: str


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
    email: Union[ConfigEmail,None] = None
    slack: Union[ConfigSlack,None] = None
    phantom: Union[ConfigPhantom,None] = None
    rba: Union[ConfigRba,None] = None


class ConfigAlertAction(BaseModel):
    notable: ConfigNotable




class ConfigDeploy(BaseModel):
    description: str = "Description for this deployment target"
    server: str = "127.0.0.1"

CREDENTIAL_MISSING = "PROVIDE_CREDENTIALS_VIA_CMD_LINE_ARGUMENT"
class ConfigDeployACS(ConfigDeploy):
    token: str = CREDENTIAL_MISSING
    

class ConfigDeployRestAPI(ConfigDeploy):
    port: int = 8089
    username: str = "admin"
    password: str = PASSWORD
    

class Deployments(BaseModel):
    acs_deployments: list[ConfigDeployACS] = []
    rest_api_deployments: list[ConfigDeployRestAPI] = [ConfigDeployRestAPI()]



class ConfigBuildSplunk(BaseModel):
    pass
    
class ConfigBuildJson(BaseModel):
    pass

class ConfigBuildBa(BaseModel):
    pass



class ConfigBuild(BaseModel):
    # Fields required for app.conf based on
    # https://docs.splunk.com/Documentation/Splunk/9.0.4/Admin/Appconf
    name: str = Field(default="ContentPack",title="Internal name used by your app.  No spaces or special characters.")
    path_root: str = Field(default="dist",title="The root path at which you will build your app.")
    prefix: str = Field(default="ContentPack",title="A short prefix to easily identify all your content.")
    build: int = Field(default=int(datetime.utcnow().strftime("%Y%m%d%H%M%S")),
                       title="Build number for your app.  This will always be a number that corresponds to the time of the build in the format YYYYMMDDHHMMSS")
    version: str = Field(default="0.0.1",title="The version of your Content Pack.  This must follow semantic versioning guidelines.")
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
    id: str = Field(default="ContentPack",title="Internal name used by your app.  No spaces or special characters.")
    label: str = Field(default="Custom Splunk Content Pack",title="This is the app name that shows in the launcher.")
    author_name: str = Field(default="author name",title="Name of the Content Pack Author.")
    author_email: str = Field(default="author@contactemailaddress.com",title="Contact email for the Content Pack Author")
    author_company: str = Field(default="author company",title="Name of the company who has developed the Content Pack")
    description: str = Field(default="description of app",title="Free text description of the Content Pack.")

    splunk_app: Union[ConfigBuildSplunk,None] = ConfigBuildSplunk()
    json_objects: Union[ConfigBuildJson,None] = None
    ba_objects: Union[ConfigBuildBa,None] = None

    @validator('version', always=True)
    def validate_version(cls, v, values):
        try:
            validate_version = semantic_version.Version(v)
        except Exception as e:
            raise(ValueError(f"The specified version does not follow the semantic versioning spec (https://semver.org/). {str(e)}"))
        return v



class ConfigEnrichments(BaseModel):
    attack_enrichment: bool = False
    cve_enrichment: bool = False
    splunk_app_enrichment: bool = False



class Config(BaseModel, extra=Extra.forbid):
    #general: ConfigGlobal = ConfigGlobal()
    detection_configuration: ConfigDetectionConfiguration = ConfigDetectionConfiguration()
    deployments: Deployments = Deployments()
    build: ConfigBuild = ConfigBuild()
    enrichments: ConfigEnrichments = ConfigEnrichments()
    test: Union[TestConfig,None] = None 
    


