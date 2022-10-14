import string
import uuid
import requests
import pathlib
import re

from pydantic import BaseModel, validator, ValidationError, Extra, Field
from dataclasses import dataclass
from datetime import datetime
from typing import Union
import validators
from bin.objects.security_content_object import SecurityContentObject
from bin.objects.enums import SecurityContentProduct
from bin.objects.app import App
from bin.objects.enums import DataModel
from semantic_version import Version
import argparse 

SPLUNKBASE_URL = "https://splunkbase.splunk.com/app/{uid}/release/{release}/download"

class Manifest(BaseModel, extra=Extra.forbid):
    #Note that many of these fields are mirrored from App

    #Some information about the developer of the app 
    author_name: str = Field(default=None, title="Enter the name of the app author")
    author_email: str = Field(default=None, title="Enter a contact email for the develop(s) of the app")
    author_company: str = Field(default=None, title="Enter the company who is developing the app")

    #uid is a numeric identifier assigned by splunkbase, so
    #homemade applications will not have this
    uid: Union[int, None] = Field(default=None, title="Unique numeric identifier assigned by Splunkbase to identify your app. You can find it in the URL of your app's landing page.  If you do not have one, leave this blank.")

    #appid is basically the internal name of you app
    appid: str = Field(default=None, title="Internal name of your app.  Note that it MUST be alphanumeric with underscores, but no spaces or other special characters")
    
    #Title is the human readable name for your application
    title: str = Field(default=None, title="Human-Readable name for your app. This can include any characters you want")

    #Self explanatory
    description: Union[str,None] = Field(default=None, title="Provide a helpful description of the app.")
    release: str = Field(default=None, title="Provide a name for the current release of the app.  This MUST follow semantic version format MAJOR.MINOR.PATCH[-tag]")

    @validator('author_email', always=True)
    def validate_author_email(cls, v):
        if bool(validators.email.email(v)) == False:
            raise(ValueError(f"Email address {v} is invalid"))
        return v
    
    @validator('release', always=True)
    def validate_release(cls, v):
        try:    
            Version(v)
        except Exception as e:
            raise(ValueError(f"The string '{v}' is not a valid Semantic Version.  For more information on Semantic Versioning, please refer to https://semver.org/"))
        
        return v


class AppBuilder(BaseModel, extra=Extra.forbid):

    #Needs a manifest to be able to properly generate the app
    manifest:Manifest

    
    
    type: SecurityContentProduct = Field(default=SecurityContentProduct.SPLUNK_ENTERPRISE_APP, title=f"What type of product would you like to build.  Choose one of {SecurityContentProduct._member_names_}")
    skip_enrichment: bool = Field(default=True, title="Whether or not to skip the enrichment processes when validating the app.  Enrichment increases the amount of time it takes to build an app significantly because it must hit a number of Web APIs.")

    input_path: str = Field(default='.', title="Path to the root of your app")
    output_path: str = Field(default='./dist', title="Path where 'generate' will write out your raw app")
    #output_path: str = Field(default='./build', title="Path where 'build' will write out your custom app")
    

    @staticmethod
    def create_argparse_parser_from_model(parser: argparse.ArgumentParser):
        #Add all the fields defined in the model as arguments to the parser
        parser.add_argument("-c", "--config_file", type=argparse.FileType('r'), default=None, help="Name of the config file to run the test")
        
        #Expose the appBuilder Fields
        for fieldName, fieldItem in AppBuilder.__fields__.items():
            parser.add_argument(f"--{fieldName}", type=fieldItem.type_, default=None, help=fieldItem.field_info.title)

        #Expose the Manifest Fields
        for fieldName, fieldItem in Manifest.__fields__.items():
            parser.add_argument(f"--{fieldName}", type=fieldItem.type_, default=None, help=fieldItem.field_info.title)
        
        


    @staticmethod
    def validate_string_alphanumeric_with_underscores(input:str)->bool:
        if len(input) == 0:
            raise(ValueError(f"String was length 0"))

        for letter in input:
            if not (letter.isalnum() or letter =='_'):
                raise(ValueError("String can only contain alphanumeric characters and underscores"))
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
        
        #release can be any string
        return v
    
    @validator('http_path', always=True)
    def validate_http_path(cls, v, values):
        if v is not None:
            try:
                if bool(validators.url(v)) == False:
                    raise Exception(f"URL '{v}' is not a valid URL")
            except Exception as e:
                raise(ValueError(f"Error validating the http_path: {str(e)}"))
        return v
    

    @validator('must_download_from_splunkbase', always=True)
    def validate_must_download_from_splunkbase(cls, v, values):
        if values['local_path'] is None and values['http_path'] is None:
            return True
        else:
            return False



    @validator('splunkbase_path', always=True)
    def validate_splunkbase_path(cls, v, values):
        
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
                                    f" build the url for '{values['name']}', but no "\
                                    f"uid was supplied."))
            else:
                return None

        if values['release'] is None:
            if must_download:
                raise(ValueError(f"Error building splunkbase_url. Attempting to"\
                                    f" build the url for '{values['name']}', but no "\
                                    f"release was supplied."))
            else:
                return None
        return SPLUNKBASE_URL.format(uid=values['uid'], release = values['release'])
        