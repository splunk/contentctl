from typing import Dict, Any

import yaml


import sys
import pathlib

class YmlReader():

    @staticmethod
    def load_file(file_path: pathlib.Path, add_fields=True, STRICT_YML_CHECKING=False) -> Dict[str,Any]:
        try:
            file_handler = open(file_path, 'r', encoding="utf-8")
            
            # The following code can help diagnose issues with duplicate keys or 
            # poorly-formatted but still "compliant" YML.  This code should be
            # enabled manually for debugging purposes. As such, strictyaml 
            # library is intentionally excluded from the contentctl requirements

            if STRICT_YML_CHECKING:
                import strictyaml
                try:
                    strictyaml.dirty_load(file_handler.read(), allow_flow_style = True)
                    file_handler.seek(0)
                except Exception as e:
                    print(f"Error loading YML file {file_path}: {str(e)}")
                    sys.exit(1)
            try:
                #yml_obj = list(yaml.safe_load_all(file_handler))[0]
                yml_obj = yaml.load(file_handler, Loader=yaml.CSafeLoader)
            except yaml.YAMLError as exc:
                print(exc)
                sys.exit(1)

        except OSError as exc:
            print(exc)
            sys.exit(1)
        
        if add_fields == False:
            return yml_obj
        
        
        yml_obj['file_path'] = str(file_path)
    

        return yml_obj
