import os
import collections
import sys
import pathlib

from contentctl.input.yml_reader import YmlReader
from contentctl.objects.config import Config, TestConfig


class ConfigHandler:

    @classmethod
    def read_config(cls, config_path: pathlib.Path) -> Config:
        try:
            yml_dict = YmlReader.load_file(config_path, add_fields=False)

        except:
            print("ERROR: no contentctl.yml found in given path")
            sys.exit(1)

        try: 
            config = Config.parse_obj(yml_dict)
        except Exception as e:
            raise Exception(f"Error reading config file: {str(e)}")
            

        return config
    
    @classmethod
    def read_test_config(cls, test_config_path: pathlib.Path) -> TestConfig:
        try:
            yml_dict = YmlReader.load_file(test_config_path, add_fields=False)
        except:
            print("ERROR: no contentctl_test.yml found in given path")
            sys.exit(1)

        try: 
            test_config = TestConfig.parse_obj(yml_dict)
        except Exception as e:
            raise Exception(f"Error reading test config file: {str(e)}")
            

        return test_config
    

          
 
 