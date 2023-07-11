import os
import collections
import sys
import pathlib

from contentctl.input.yml_reader import YmlReader
from contentctl.objects.config import Config


class ConfigHandler:

    @classmethod
    def read_config(cls, config_path: pathlib.Path, validate_test:bool=False) -> Config:
        try:
            yml_dict = YmlReader.load_file(config_path)
        except:
            print("ERROR: no contentctl.yml found in given path")
            sys.exit(1)

        try: 
            if validate_test == False:
                yml_dict.pop("test")
            config = Config.parse_obj(yml_dict)
        except Exception as e:
            print(e)
            sys.exit(1)

        return config

          
 
 