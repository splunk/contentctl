import os
import collections
import sys


from splunk_contentctl.input.yml_reader import YmlReader
from splunk_contentctl.objects.config import Config


class ConfigHandler:

    @classmethod
    def read_config(cls, config_path: str) -> Config:
        try:
            yml_dict = YmlReader.load_file(config_path)
        except:
            print("ERROR: no contentctl.yml found in given path")
            sys.exit(1)

        try: 
            config = Config.parse_obj(yml_dict)
        except Exception as e:
            print(e)
            sys.exit(1)

        return config

          
 
 