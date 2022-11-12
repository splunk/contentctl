import os
import collections
import sys


from splunk_contentctl.input.yml_reader import YmlReader


class ConfigHandler:

    @classmethod
    def read_config(self, config_path: str) -> dict:
        yml_dict_default = YmlReader.load_file(os.path.join(os.path.dirname(__file__), '../templates/contentctl_default.yml'))

        try:
            yml_dict = YmlReader.load_file(os.path.join(os.path.dirname(__file__), '../../', config_path))
        except:
            print("no config file found, running with default from templates/contentctl_default.yml")
            yml_dict = ''

        parent_keys = ['global', 'content', 'scheduling', 'alert_actions', 'test', 'deploy', 'build', 'enrichment', 'custom_validators']

        for parent_key in parent_keys:
            if parent_key in yml_dict:
                for key in yml_dict[parent_key]:
                    yml_dict_default[parent_key][key] = yml_dict[parent_key][key]

        yml_dict_default.pop('file_path')
        yml_dict_default.pop('deprecated')
        yml_dict_default.pop('experimental')
        return yml_dict_default

    @classmethod
    def validate_config(self, config: dict) -> None:
        if 'notable' not in config['alert_actions']:
            print("ERROR: unsupported alert_action, please use notable, email, or risk.")
            sys.exit(1)             
 
 