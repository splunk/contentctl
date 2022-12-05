from pydantic import BaseModel, validator, ValidationError


class ConfigGlobal(BaseModel):
    log_path: str
    log_level: str


class ConfigScheduling(BaseModel):
    cron_schedule: str
    earliest_time: str
    latest_time: str
    schedule_window: str


class ConfigAlertActionNotable(BaseModel):
    rule_description: str
    rule_title: str
    nes_fields: list


class ConfigAlertAction(BaseModel):
    notable: ConfigAlertActionNotable


class ConfigTest(BaseModel):
    docker_image: str
    apps: list
    assets: str


class ConfigDeploy(BaseModel):
    target: str
    username: str
    password: str
    server: str


class ConfigBuildSplunk(BaseModel):
    path: str
    name: str
    prefix: str
    author: str
    author_email: str


class ConfigBuildJson(BaseModel):
    path: str


class ConfigBuildBa(BaseModel):
    path: str


class ConfigBuild(BaseModel):
    splunk_app: ConfigBuildSplunk
    json_objects: ConfigBuildJson
    ba_objects: ConfigBuildBa


class ConfigEnrichments(BaseModel):
    attack_enrichment: bool
    cve_enrichment: bool
    splunk_app_enrichment: bool



class Config(BaseModel):
    general: ConfigGlobal
    scheduling: ConfigScheduling
    alert_actions: ConfigAlertAction
    test: ConfigTest
    deploy: ConfigDeploy
    build: ConfigBuild
    enrichments: ConfigEnrichments

