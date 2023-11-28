import configparser
import pathlib
import re
import sys

from typing import List


class ConfReader():

    @staticmethod
    def load_file(file_path: pathlib.Path) -> List:
        try:
            with open(file_path, 'r') as f:
                conf = re.sub(r'^\|', '\t|', f.read(), flags=re.MULTILINE)
                conf = re.sub(r' \\$', ' ', conf, flags=re.MULTILINE)
            config = configparser.ConfigParser()
            config.read_string(conf)
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
