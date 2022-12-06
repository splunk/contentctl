import os
import collections
import sys


from splunk_contentctl.input.yml_reader import YmlReader
from splunk_contentctl.objects.config import Config


class ConfigHandler:

    @classmethod
    def read_config(cls, config_path: str) -> Config:
        yml_dict_default = YmlReader.load_file(os.path.join(os.path.dirname(__file__), '../templates/contentctl_default.yml'))

        try:
            yml_dict = YmlReader.load_file(os.path.join(os.path.dirname(__file__), '../', config_path))
        except:
            print("no config file found, running with default from templates/contentctl_default.yml")
            yml_dict = yml_dict_default

        try: 
            config = Config.parse_obj(yml_dict)
        except Exception as e:
            print(e)
            sys.exit(1)

        return config

          
 
 