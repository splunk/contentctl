import json
from contentctl.objects.abstract_security_content_objects.security_content_object_abstract import SecurityContentObject_Abstract
from typing import List
from io import TextIOWrapper
class JsonWriter():

    @staticmethod
    def writeJsonObject(file_path : str, objs: dict[str, List[dict]]) -> None:
        try:
            with open(file_path, 'w') as outfile:
                json.dump(objs, outfile, ensure_ascii=False)
        except Exception as e:
             raise Exception(f"Error serializing object to Json File '{file_path}': {str(e)}")
            