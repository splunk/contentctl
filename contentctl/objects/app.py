# Needed for a staticmethod to be able to return an instance of the class it belongs to
from __future__ import annotations


import pathlib
import re
import os

from pydantic import BaseModel, validator, ValidationError, Extra, Field
from dataclasses import dataclass
from datetime import datetime
from typing import Union
import validators
from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.objects.enums import DataModel
from contentctl.helper.utils import Utils
import yaml

SPLUNKBASE_URL = "https://splunkbase.splunk.com/app/{uid}/release/{release}/download"
ENVIRONMENT_PATH_NOT_SET = "ENVIRONMENT_PATH_NOT_SET"

class App(BaseModel, extra=Extra.forbid):

    # uid is a numeric identifier assigned by splunkbase, so
    # homemade applications will not have this
    uid: Union[int, None]

    # appid is basically the internal name of your app
    appid: str

    # Title is the human readable name for your application
    title: str

    # Self explanatory
    description: Union[str, None]
    release: str

    local_path: Union[str, None]
    http_path: Union[str, None]
    # Splunkbase path is made of the combination of uid and release fields
    splunkbase_path: Union[str, None]

    # Ultimate source of the app. Can be a local path or a Splunkbase Path.
    # This will be set via a function call and should not be provided in the YML
    # Note that this is the path relative to the container mount
    environment_path: str = ENVIRONMENT_PATH_NOT_SET
    force_local:bool = False

    def configure_app_source_for_container(
        self,
        splunkbase_username: Union[str, None],
        splunkbase_password: Union[str, None],
        apps_directory: pathlib.Path,
        container_mount_path: pathlib.Path,
    ):

        splunkbase_creds_provided = (
            splunkbase_username is not None and splunkbase_password is not None
        )

        if splunkbase_creds_provided and self.splunkbase_path is not None and not self.force_local:
            self.environment_path = self.splunkbase_path

        elif self.local_path is not None:
            # local path existence already validated
            filename = pathlib.Path(self.local_path)
            destination = str(apps_directory / filename.name)
            Utils.copy_local_file(self.local_path, destination, verbose_print=True)
            self.environment_path = str(container_mount_path / filename.name)

        elif self.http_path is not None:
            from urllib.parse import urlparse

            path_on_server = str(urlparse(self.http_path).path)
            filename = pathlib.Path(path_on_server)
            download_path = str(apps_directory / filename.name)
            Utils.download_file_from_http(self.http_path, download_path)
            self.environment_path = str(container_mount_path / filename.name)

        else:
            raise (
                Exception(
                    f"Unable to download app {self.title}:\n"
                    f"Splunkbase Path : {self.splunkbase_path}\n"
                    f"local_path      : {self.local_path}\n"
                    f"http_path       : {self.http_path}\n"
                    f"Splunkbase Creds: {splunkbase_creds_provided}\n"
                )
            )

    @staticmethod
    def validate_string_alphanumeric_with_underscores(input: str) -> bool:
        if len(input) == 0:
            raise (ValueError(f"String was length 0"))

        for letter in input:
            if not (letter.isalnum() or letter in "_-"):
                raise (
                    ValueError(
                        f"String '{input}' can only contain alphanumeric characters, underscores, and hyphens."
                    )
                )
        return True

    @validator("uid", always=True)
    def validate_uid(cls, v):
        return v

    @validator("appid", always=True)
    def validate_appid(cls, v):
        # Called function raises exception on failure, so we don't need to raise it here
        cls.validate_string_alphanumeric_with_underscores(v)
        return v

    @validator("title", always=True)
    def validate_title(cls, v):
        # Basically, a title can be any string
        return v

    @validator("description", always=True)
    def validate_description(cls, v):
        # description can be anything
        return v

    @validator("release", always=True)
    def validate_release(cls, v):
        # release can be any string
        return v

    @validator("local_path", always=True)
    def validate_local_path(cls, v):
        if v is not None:
            p = pathlib.Path(v)
            if not p.exists():
                raise (ValueError(f"The path local_path {p} does not exist"))
            elif not p.is_file():
                raise (ValueError(f"The path local_path {p} exists, but is not a file"))

        # release can be any string
        return v

    @validator("http_path", always=True)
    def validate_http_path(cls, v, values):
        if v is not None:
            try:
                if bool(validators.url(v)) == False:
                    raise ValueError(f"URL '{v}' is not a valid URL")
            except Exception as e:
                raise (ValueError(f"Error validating the http_path: {str(e)}"))
        return v

    @validator("splunkbase_path", always=True)
    def validate_splunkbase_path(cls, v, values):
        Utils.check_required_fields(
            "splunkbase_path", values, ["local_path", "http_path", "uid", "title"]
        )

        if v is not None:
            try:
                if bool(validators.url(v)) == False:
                    raise ValueError(f"splunkbase_url {v} is not a valid URL")
            except Exception as e:
                raise (ValueError(f"Error validating the splunkbase_url: {str(e)}"))

            if (
                bool(
                    re.match(
                        "^https://splunkbase\.splunk\.com/app/\d+/release/.+/download$",
                        v,
                    )
                )
                == False
            ):
                raise (
                    ValueError(
                        f"splunkbase_url {v} does not match the format {SPLUNKBASE_URL}"
                    )
                )

        # Try to form the URL and error out if Splunkbase is the only place to get the app
        if values["uid"] is None:
            if values["must_download_from_splunkbase"]:
                raise (
                    ValueError(
                        f"Error building splunkbase_url. Attempting to"
                        f" build the url for '{values['title']}', but no "
                        f"uid was supplied."
                    )
                )
            else:
                return None

        if values["release"] is None:
            if values["must_download_from_splunkbase"]:
                raise (
                    ValueError(
                        f"Error building splunkbase_url. Attempting to"
                        f" build the url for '{values['title']}', but no "
                        f"release was supplied."
                    )
                )
            else:
                return None
        return SPLUNKBASE_URL.format(uid=values["uid"], release=values["release"])

    @staticmethod
    def get_default_apps() -> list[App]:
        all_app_objs: list[App] = []
        with open(
            os.path.join(os.path.dirname(__file__), "../", "templates/app_default.yml"),
            "r",
        ) as app_data:
            all_apps_raw = yaml.safe_load(app_data)
            for a in all_apps_raw:
                app_obj = App.parse_obj(a)
                all_app_objs.append(app_obj)
        return all_app_objs
