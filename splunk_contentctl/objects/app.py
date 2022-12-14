#Needed for a staticmethod to be able to return an instance of the class it belongs to
from __future__ import annotations


import pathlib
import re

from pydantic import BaseModel, validator, ValidationError, Extra, Field
from dataclasses import dataclass
from datetime import datetime
from typing import Union
import validators
from splunk_contentctl.objects.security_content_object import SecurityContentObject
from splunk_contentctl.objects.enums import DataModel
from splunk_contentctl.helper.utils import Utils
import yaml

SPLUNKBASE_URL = "https://splunkbase.splunk.com/app/{uid}/release/{release}/download"



class App(BaseModel, extra=Extra.forbid):
    

    #uid is a numeric identifier assigned by splunkbase, so
    #homemade applications will not have this
    uid: Union[int, None] 

    #appid is basically the internal name of you app
    appid: str
    
    #Title is the human readable name for your application
    title: str

    #Self explanatory
    description: Union[str,None]
    release: str


    local_path: Union[str,None]
    http_path: Union[str,None]
    #Splunkbase path is made of the combination of uid and release fields
    splunkbase_path: Union[str,None]
    
    must_download_from_splunkbase: bool = True

    @staticmethod
    def validate_string_alphanumeric_with_underscores(input:str)->bool:
        if len(input) == 0:
            raise(ValueError(f"String was length 0"))

        for letter in input:
            if not (letter.isalnum() or letter in '_-' ):
                raise(ValueError(f"String '{input}' can only contain alphanumeric characters, underscores, and hyphens."))
        return True

    @validator('uid', always=True)
    def validate_uid(cls, v):
        return v

    @validator('appid', always=True)
    def validate_appid(cls, v):
        #Called function raises exception on failure, so we don't need to raise it here
        cls.validate_string_alphanumeric_with_underscores(v)
        return v
        

    @validator('title', always=True)
    def validate_title(cls, v):
        #Basically, a title can be any string
        return v

    @validator('description', always=True)
    def validate_description(cls, v):
        #description can be anything
        return v
    

    @validator('release', always=True)
    def validate_release(cls, v):
        #release can be any string
        return v

    @validator('local_path', always=True)
    def validate_local_path(cls, v):
        if v is not None:
            p = pathlib.Path(v)
            if not p.exists():
                raise(ValueError(f"The path local_path {p} does not exist"))
            elif not p.is_file():
                raise(ValueError(f"The path local_path {p} exists, but is not a file"))
            
        
        #release can be any string
        return v
    
    @validator('http_path', always=True)
    def validate_http_path(cls, v, values):
        if v is not None:
            try:
                if bool(validators.url(v)) == False:
                    raise ValueError(f"URL '{v}' is not a valid URL")
            except Exception as e:
                raise(ValueError(f"Error validating the http_path: {str(e)}"))
        return v
    

    @validator('must_download_from_splunkbase', always=True)
    def validate_must_download_from_splunkbase(cls, v, values):
        Utils.check_required_fields('must_download_from_splunkbase', values, ['local_path', 'http_path'])

        if values['local_path'] is None and values['http_path'] is None:
            return True
        else:
            return False



    @validator('splunkbase_path', always=True)
    def validate_splunkbase_path(cls, v, values):
        Utils.check_required_fields('splunkbase_path', values, ['local_path', 'http_path', 'uid', 'title'])

        if v is not None:
            try:
                res = bool(validator.url(v))
                if res is False:
                    raise Exception
            except Exception as e:
                raise(ValueError(f"splunkbase_url {v} is not a valid URL"))

            if bool(re.match("^https://splunkbase\.splunk\.com/app/\d+/release/.+/download$",v)) == False:
                raise(ValueError(f"splunkbase_url {v} does not match the format {SPLUNKBASE_URL}"))


        #Check to see if we MUST get this from splunkbase
        if values['local_path'] is None and values['http_path'] is None:
            must_download = True
        else:
            must_download = False


        #Try to form the URL and error out if Splunkbase is the only place to get the app
        if values['uid'] is None:
            if must_download:
                raise(ValueError(f"Error building splunkbase_url. Attempting to"\
                                    f" build the url for '{values['title']}', but no "\
                                    f"uid was supplied."))
            else:
                return None

        if values['release'] is None:
            if must_download:
                raise(ValueError(f"Error building splunkbase_url. Attempting to"\
                                    f" build the url for '{values['title']}', but no "\
                                    f"release was supplied."))
            else:
                return None
        return SPLUNKBASE_URL.format(uid=values['uid'], release = values['release'])
        
    @staticmethod
    def get_default_apps()->list[App]:
        all_app_objs:list[App] = []
        with open("templates/app_default.yml", "r") as app_data:
            all_apps_raw = yaml.safe_load(app_data)
            for a in all_apps_raw:
                app_obj = App.parse_obj(a)
                all_app_objs.append(app_obj)
        return all_app_objs
    