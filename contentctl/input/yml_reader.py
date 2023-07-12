from typing import Dict

import yaml
import sys
import pathlib

class YmlReader():

    @staticmethod
    def load_file(file_path: pathlib.Path, add_fields=True) -> Dict:
        try:
            file_handler = open(file_path, 'r', encoding="utf-8")
            try:
                yml_obj = list(yaml.safe_load_all(file_handler))[0]
            except yaml.YAMLError as exc:
                print(exc)
                sys.exit(1)

        except OSError as exc:
            print(exc)
            sys.exit(1)
        
        if add_fields == False:
            return yml_obj
        
        yml_obj['file_path'] = str(file_path)
        
        if 'deprecated' in [parent.name for parent in file_path.parents]:
            yml_obj['deprecated'] = True
        else:
            yml_obj['deprecated'] = False

        if 'experimental' in [parent.name for parent in file_path.parents]:
            yml_obj['experimental'] = True
        else:
            yml_obj['experimental'] = False

        return yml_obj
