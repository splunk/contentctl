
import yaml
from typing import Any

class YmlWriter:

    @staticmethod
    def writeYmlFile(file_path : str, obj : dict[Any,Any]) -> None:

        with open(file_path, 'w') as outfile:
            yaml.safe_dump(obj, outfile, default_flow_style=False, sort_keys=False)