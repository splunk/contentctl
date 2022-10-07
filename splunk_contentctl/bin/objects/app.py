from msilib.schema import AppId
import string
import uuid
import requests
import pathlib
import re

from pydantic import BaseModel, validator, ValidationError
from dataclasses import dataclass
from datetime import datetime
from typing import Union
import validators
from bin.objects.security_content_object import SecurityContentObject
from bin.objects.enums import DataModel

SPLUNKBASE_URL = "https://splunkbase.splunk.com/app/{uid}/release/{release}/download"

class App(BaseModel):
    # baseline spec
    name: str

    
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
    

    def validate_string_alphanumeric_with_underscores(self, input:str)->bool:
        if len(input) == 0:
            raise(ValueError(f"String was length 0"))

        for letter in input:
            if not (letter.isalnum() or letter =='_'):
                raise(ValueError("String can only contain alphanumeric characters and underscores"))
        return True

    @validator('uid')
    def validate_uid(cls, v):
        return v

    @validator('appid')
    def validate_appid(cls, v):
        #Called function raises exception on failure, so we don't need to raise it here
        cls.validate_string_alphanumeric_with_underscores(v)
        return v
        

    @validator('title')
    def validate_title(cls, v):
        #Basically, a title can be any string
        return v

    @validator('description')
    def validate_description(cls, v):
        #description can be anything
        return v
    

    @validator('release')
    def validate_release(cls, v):
        #release can be any string
        return v

    @validator('local_path')
    def validate_local_path(cls, v):
        if v is not None:
            p = pathlib.Path(v)
            if not p.exists():
                raise(ValueError(f"The path local_path {p} does not exist"))
        #release can be any string
        return v
    
    @validator('http_path')
    def validate_http_path(cls, v, values):
        if values['local_path'] is not None:
            #local_path takes precedence over http path, so we will skip validating http path
            return v

        if v is not None:
            try:
                validators.url(v)
            except Exception as e:
                raise(ValueError(f"Error validating the http_path: {v}"))
        return v
    
    @validator('splunkbase_rul')
    def validate_splunkbase_path(cls, v, values):
        if values['local_path'] is None and values['http_path'] is None:
            #We must get this from splunkbase
            if values['uid'] is None:
                raise(ValueError(f"Error building splunkbase_url. Attempting to"\
                                 f" build the url for '{values['name']}', but no "\
                                 f"uid was supplied."))
            if values['release'] is None:
                raise(ValueError(f"Error building splunkbase_url. Attempting to"\
                                 f" build the url for '{values['name']}', but no "\
                                 f"release was supplied."))
            return SPLUNKBASE_URL.format(uid=values['uid'], release = values['release'])
        
        
        try:
            validator.url(v)
        except Exception as e:
            raise(ValueError(f"splunkbase_url {v} is not a valid URL"))

        if bool(re.match("^https://splunkbase\.splunk\.com/app/\d+/release/.+/download$",v)) == False:
            raise(ValueError(f"splunkbase_url {v} does not match the format {SPLUNKBASE_URL}"))

        return v

            
        

            