import pathlib
import re
import sys

from typing import List

from addonfactory_splunk_conf_parser_lib import TABConfigParser


class ConfReader():

    @staticmethod
    def load_file(file_path: pathlib.Path) -> List:
        try:
            with open(file_path, 'r') as f:
                conf_file = f.read()
            config = TABConfigParser()
            config.read_string(conf_file)
            conf_obj = []
            for section_name in config.sections():
                obj = {'name': section_name.split(' - ')[1].strip()}
                for key, value in config[section_name].items():
                    if key in (
                        'disabled',
                        'action.send_notable_to_mc_alert_action',
                        'action.add_events',
                        'alert.suppress',
                    ):
                        obj[key] = bool(value)
                    else:
                        obj[key] = value
                conf_obj.append(obj)
        except OSError as exc:
            print(exc)
            sys.exit(1)

        return conf_obj
