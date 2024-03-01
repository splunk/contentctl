# Needed for a staticmethod to be able to return an instance of the class it belongs to
from __future__ import annotations
from typing import Union,Optional, Annotated, TYPE_CHECKING, Self
if TYPE_CHECKING:
    from contentctl.objects.config import Config
    from contentctl.objects.test_config import TestConfig

from urllib.parse import urlparse

import pathlib
import re
import os

from pydantic import BaseModel, validator, FilePath, computed_field, HttpUrl,Field


from contentctl.helper.utils import Utils
import yaml
import validators

SPLUNKBASE_URL = "https://splunkbase.splunk.com/app/{uid}/release/{release}/download"
ENVIRONMENT_PATH_NOT_SET = "ENVIRONMENT_PATH_NOT_SET"

class App(BaseModel, extra="forbid"):

    # uid is a numeric identifier assigned by splunkbase, so
    # homemade applications will not have this
    uid: Annotated[int, Field(gt=1,lt=100000)]

    # appid is basically the internal name of your app
    appid: Optional[Annotated[str,Field(pattern="^[a-zA-Z0-9_-]+$")]]

    # Title is the human readable name for your application
    title: Annotated[str,Field(min_length=1)]

    # Self explanatory
    description: Optional[Annotated[str,Field(min_length=1)]] = None
    release: Annotated[str,Field(min_length=1)]

    hardcoded_path: Optional[Union[FilePath,HttpUrl]]
    
    # Splunkbase path is made of the combination of uid and release fields
    @computed_field
    @property
    def splunkbase_path(self)->Optional[HttpUrl]:
        if self.uid is not None and self.release is not None:
            return HttpUrl(SPLUNKBASE_URL.format(uid=self.uid,release=self.release))
        return None

    
    @classmethod
    def appFromConfig(cls, config:Config):
        
        return cls(uid=config.build.uid, 
                   appid=config.build.name, 
                   title=config.build.title, 
                   description=config.build.description, 
                   release=config.build.version,
                   hardcoded_path=FilePath("dist/DA-ESS-ContentUpdate-latest.tar.gz"))
    


    def get_app_source(
        self,
        config:Config,
        apps_directory: pathlib.Path,
        container_mount_path: pathlib.Path,
    )->str:

        assert config.test is not None, f"Error - config.test was 'None'. It should be an instance of TestConfig."

        test_config:TestConfig = config.test


        if test_config.splunkbase_password is not None and \
            test_config.splunkbase_username is not None:
            if self.appid == config.build.name:
                # This is a special case.  This is the app that we have
                # just built, which we obviously CANNOT get from splunkbase!

                pass
            else:
                return str(self.splunkbase_path)


        if isinstance(self.hardcoded_path, FilePath):
            filename = pathlib.Path(self.hardcoded_path)
            destination = apps_directory / filename.name
            Utils.copy_local_file(str(self.hardcoded_path), str(destination), verbose_print=True)
        
        elif isinstance(self.hardcoded_path, HttpUrl):
            
            file_url_string = str(self.hardcoded_path)
            server_path = pathlib.Path(urlparse(file_url_string).path)
            destination = apps_directory / server_path.name
            Utils.download_file_from_http(file_url_string, str(destination))
        
        else:
            raise (
                Exception(
                    f"Unable to download app {self.title}:\n"
                    f"Splunkbase Path : {self.splunkbase_path}\n"
                    f"hardcoded_path  : {self.hardcoded_path}\n"
                    f"Splunkbase Creds: {False}\n"
                )
            )

        return str(container_mount_path/destination.name)
        
    @staticmethod
    def get_default_apps() -> list[App]:
        return []
        all_app_objs: list[App] = []
        with open(
            os.path.join(os.path.dirname(__file__), "../", "templates/app_default.yml"),
            "r",
        ) as app_data:
            all_apps_raw = yaml.safe_load(app_data)
            for a in all_apps_raw:
                app_obj = App.model_validate(a)
                all_app_objs.append(app_obj)
        return all_app_objs
