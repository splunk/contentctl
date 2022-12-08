
import validators
import pathlib
import git
import yaml
import os 
from pydantic import BaseModel, validator, root_validator, Extra, Field
from dataclasses import dataclass
from typing import Union
import docker
import argparse
import docker.errors
import requests
import datetime

from splunk_contentctl.objects.enums import PostTestBehavior, DetectionTestingMode, DetectionTestingTargetInfrastructure
from splunk_contentctl.helper.utils import Utils










from typing import Union
class AttackDataCache(BaseModel, extra=Extra.forbid):
    cache_file_uri: str = "https://media.githubusercontent.com/media/splunk/attack_data/master/alldata.zip"
    cache_file_system_location: str = "/tmp/archiveFun/alldata.zip"
    cache_update_time: Union[str,None] = "DATETIME REPRESENTATION FOR COMPARISON WITH HEAD.GET"
    cache_valid: bool = False
    cache_file_uri_prefix:str = "https://media.githubusercontent.com/media/splunk/attack_data/master/"
    

    @root_validator(pre=False)
    def validate_cache(cls, values):
        #Check to see if we can reach the uri for the cache file
        try:
            r = requests.head(values['cache_file_uri'])
            if r.status_code > 400:
                raise(Exception(f"Status code was {r.status_code}"))            
            cache_file_uri_success = True

        except Exception as e:
            print(f"Error checking the cache_file_uri {values['cache_file_uri']}: {str(e)}")
            cache_file_uri_success = False
        
        #Check to see if a cache file exists
        try:
            if pathlib.Path(values['cache_file_system_location']).is_file():
                values['cache_valid'] = True
            else:
                values['cache_valid'] = False
        except Exception as e:
            print(f"Error checking for the existence of the cache file {values['cache_file_system_location']}")
            values['cache_valid'] = False
        
        #we MUST try to get the cache file if we don't have one already
        if cache_file_uri_success and not values['cache_valid']:
            Utils.download_file_from_http(values['cache_file_uri'], values['cache_file_system_location'], 
                                                 overwrite_file=True, verbose_print=True)
            values['cache_valid'] = True
            values['cache_update_time'] = datetime.datetime.now.isoformat()
            return values
            #We have refreshed the cache
        elif cache_file_uri_success and values['cache_valid']:
            Utils.warning_print("Figure out to tell using timestamp if cache at uri is newer than downloaded cache")
            Utils.download_file_from_http(values['cache_file_uri'], values['cache_file_system_location'], 
                                                 overwrite_file=True, verbose_print=True)
            #We have refreshed the cache
            values['cache_valid'] = True
            values['cache_update_time'] = datetime.datetime.now.isoformat()
            return values
        print("Unable to get the cache file")
        return values


        