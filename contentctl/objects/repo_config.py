

import pathlib


from pydantic import BaseModel, root_validator, validator, ValidationError, Extra, Field
from pydantic.main import ModelMetaclass
from dataclasses import dataclass
from datetime import datetime
from typing import Union

import validators

from contentctl.objects.enums import SecurityContentProduct

from contentctl.helper.utils import Utils  

from semantic_version import Version

import git
ALWAYS_PULL = True

SPLUNKBASE_URL = "https://splunkbase.splunk.com/app/{uid}/release/{release}/download"

class Manifest(BaseModel):
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
        print("email is")
        print(v)
        if bool(validators.email(v)) == False:
            raise(ValueError(f"Email address {v} is invalid"))
        return v
    
    @validator('release', always=True)
    def validate_release(cls, v):
        try:    
            Version(v)
        except Exception as e:
            raise(ValueError(f"The string '{v}' is not a valid Semantic Version.  For more information on Semantic Versioning, please refer to https://semver.org/"))
        
        return v


class RepoConfig(BaseModel):

    #Needs a manifest to be able to properly generate the app
    manifest:Manifest = Field(default=None, title="Manifest Object")
    repo_path: str = Field(default='.', title="Path to the root of your app")
    repo_url: Union[str,None] = Field(default=None, title="HTTP(s) path to the repo for repo_path.  If this field is blank, it will be inferred from the repo")
    main_branch: str = Field(title="Main branch of the repo.")

    
    
    
    type: SecurityContentProduct = Field(default=SecurityContentProduct.SPLUNK_ENTERPRISE_APP, title=f"What type of product would you like to build.  Choose one of {SecurityContentProduct._member_names_}")
    skip_enrichment: bool = Field(default=True, title="Whether or not to skip the enrichment processes when validating the app.  Enrichment increases the amount of time it takes to build an app significantly because it must hit a number of Web APIs.")

    input_path: str = Field(default='.', title="Path to the root of your app")
    output_path: str = Field(default='./dist', title="Path where 'generate' will write out your raw app")
    #output_path: str = Field(default='./build', title="Path where 'build' will write out your custom app")

    #test_config: TestConfig = Field(default=TestConfig, title="Test Configuration")
    
    #@validator('manifest', always=True, pre=True)
    '''
    @root_validator(pre=True)
    def validate_manifest(cls, values):
        
        try:
            print(Manifest.parse_obj(values))
        except Exception as e:
            raise(ValueError(f"error validating manifest: {str(e)}"))
        

        return values
        print("TWO")
        #return {}
        #return Manifest.parse_obj({"email":"invalid_email@gmail.com"})
    '''
    @validator('repo_path', always=True)
    def validate_repo_path(cls,v):
        
        try:
            path = pathlib.Path(v)
        except Exception as e:
            raise(ValueError(f"Error, the provided path is is not a valid path: '{v}'"))
        
        try:    
            r = git.Repo(path)
        except Exception as e:
            raise(ValueError(f"Error, the provided path is not a valid git repo: '{path}'"))
        
        try:
            
            if ALWAYS_PULL:
                r.remotes.origin.pull()
        except Exception as e:
            raise ValueError(f"Error pulling git repository {v}: {str(e)}")
        
        
        return v


    @validator('repo_url', always=True)
    def validate_repo_url(cls, v, values):
        Utils.check_required_fields('repo_url', values, ['repo_path'])

        #First try to get the value from the repo
        try:
            remote_url_from_repo = git.Repo(values['repo_path']).remotes.origin.url
        except Exception as e:
            raise(ValueError(f"Error reading remote_url from the repo located at {values['repo_path']}"))
        
        if v is not None and remote_url_from_repo != v:
            raise(ValueError(f"The url of the remote repo supplied in the config file {v} does not "\
                              f"match the value read from the repository at {values['repo_path']}, {remote_url_from_repo}"))
        
        
        if v is None:    
            v = remote_url_from_repo

        #Ensure that the url is the proper format
        try:
            if bool(validators.url(v)) == False:
                raise(Exception)
        except:
            raise(ValueError(f"Error validating the repo_url. The url is not valid: {v}"))
        

        return v

    @validator('main_branch', always=True)
    def valid_main_branch(cls, v, values):
        Utils.check_required_fields('main_branch', values, ['repo_path', 'repo_url'])

        try:
            Utils.validate_git_branch_name(values['repo_path'],values['repo_url'], v)
        except Exception as e:
            raise ValueError(f"Error validating main_branch: {str(e)}")
        return v