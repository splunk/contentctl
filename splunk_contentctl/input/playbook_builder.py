
import sys
import os

from pydantic import ValidationError
from pathlib import Path

from splunk_contentctl.objects.playbook import Playbook
from splunk_contentctl.input.yml_reader import YmlReader


class PlaybookBuilder():
    playbook: Playbook
    input_path: str
    
    
    def __init__(self, input_path: str):
        self.input_path = input_path

    def setObject(self, path: str) -> None:
        yml_dict = YmlReader.load_file(path)

        try:
            self.playbook = Playbook.parse_obj(yml_dict)

        except ValidationError as e:
            print('Validation Error for file ' + path)
            print(e)
            sys.exit(1)


    def addDetections(self) -> None:
        if self.playbook.tags.detections:
            self.playbook.tags.detection_objects = []
            for detection in self.playbook.tags.detections:
                detection_object = {
                    "name": detection,
                    "lowercase_name": self.convertNameToFileName(detection),
                    "path": self.findDetectionPath(detection)
                }
                self.playbook.tags.detection_objects.append(detection_object)


    def reset(self) -> None:
        self.playbook = None


    def getObject(self) -> Playbook:
        return self.playbook


    def convertNameToFileName(self, name: str):
        file_name = name \
            .replace(' ', '_') \
            .replace('-','_') \
            .replace('.','_') \
            .replace('/','_') \
            .lower()
        return file_name


    def findDetectionPath(self, detection_name: str) -> str:
        for path in Path(os.path.join(self.input_path, 'detections')).rglob(self.convertNameToFileName(detection_name) + '.yml'):
            normalized_path = os.path.normpath(path)
            path_components = normalized_path.split(os.sep)
            value_index = path_components.index('detections')
            return "/".join(path_components[value_index:])