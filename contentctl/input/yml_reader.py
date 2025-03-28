from typing import Dict, Any
import yaml
import sys
import pathlib


class YmlReader:
    @staticmethod
    def load_file(
        file_path: pathlib.Path,
        add_fields: bool = True,
        STRICT_YML_CHECKING: bool = False,
    ) -> Dict[str, Any]:
        try: 
            file_handler = open(file_path, "r", encoding="utf-8")
        except OSError as exc:
            print(f"\nThere was an unrecoverable error when opening the file '{file_path}' - we will exit immediately:\n{str(exc)}")
            sys.exit(1)

            
        
            # The following code can help diagnose issues with duplicate keys or
            # poorly-formatted but still "compliant" YML.  This code should be
            # enabled manually for debugging purposes. As such, strictyaml
            # library is intentionally excluded from the contentctl requirements

        
        try:
            if STRICT_YML_CHECKING:
                # This is an extra level of verbose parsing that can be
                # enabled for debugging purpose. It is intentionally done in
                # addition to the regular yml parsing
                import strictyaml
                strictyaml.dirty_load(file_handler.read(), allow_flow_style=True)
                file_handler.seek(0)
            
                print(f"Error loading YML file {file_path}: {str(e)}")
                sys.exit(1)

            
            # Ideally we should use
            # from contentctl.actions.new_content import NewContent
            # and use NewContent.UPDATE_PREFIX,
            # but there is a circular dependency right now which makes that difficult.
            # We have instead hardcoded UPDATE_PREFIX
            UPDATE_PREFIX = "__UPDATE__"
            data = file_handler.read()
            if UPDATE_PREFIX in data:
                raise Exception(
                    f"\nThe file {file_path} contains the value '{UPDATE_PREFIX}'. Please fill out any unpopulated fields as required."
                )
            yml_obj = yaml.load(data, Loader=yaml.CSafeLoader)

        except yaml.YAMLError as exc:
            print(f"\nThere was an unrecoverable YML Parsing error when reading or parsing the file '{file_path}' - we will exit immediately:\n{str(exc)}")
            sys.exit(1)


        if add_fields is False:
            return yml_obj

        yml_obj["file_path"] = str(file_path)

        return yml_obj
