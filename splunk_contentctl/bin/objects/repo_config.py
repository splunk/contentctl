from email.policy import default
import string
import uuid
import requests
import pathlib
import re

from pydantic import BaseModel, validator, ValidationError, Extra, Field
from pydantic.main import ModelMetaclass
from dataclasses import dataclass
from datetime import datetime
from typing import Union
import validators
from bin.objects.security_content_object import SecurityContentObject
from bin.objects.enums import SecurityContentProduct
from bin.objects.app import App
from bin.objects.enums import DataModel
from bin.objects.test_config import TestConfig

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


class RepoConfig(BaseModel, extra=Extra.forbid):

    #Needs a manifest to be able to properly generate the app
    manifest:Manifest = Field(default=Manifest, title="manifest")
    test_config: TestConfig = Field(default=TestConfig, title="Test Configuration")
    
    
    type: SecurityContentProduct = Field(default=SecurityContentProduct.SPLUNK_ENTERPRISE_APP, title=f"What type of product would you like to build.  Choose one of {SecurityContentProduct._member_names_}")
    skip_enrichment: bool = Field(default=True, title="Whether or not to skip the enrichment processes when validating the app.  Enrichment increases the amount of time it takes to build an app significantly because it must hit a number of Web APIs.")

    input_path: str = Field(default='.', title="Path to the root of your app")
    output_path: str = Field(default='./dist', title="Path where 'generate' will write out your raw app")
    #output_path: str = Field(default='./build', title="Path where 'build' will write out your custom app")


    


