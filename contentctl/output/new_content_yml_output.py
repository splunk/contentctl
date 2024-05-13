import os
import pathlib
from contentctl.objects.enums import SecurityContentType
from contentctl.output.yml_writer import YmlWriter
import pathlib
from contentctl.objects.config import NewContentType
class NewContentYmlOutput():
    output_path: pathlib.Path
    
    def __init__(self, output_path:pathlib.Path):
        self.output_path = output_path
    
    
    def writeObjectNewContent(self, object: dict, subdirectory_name: str, type: NewContentType) -> None:
        if type == NewContentType.detection:

            file_path = os.path.join(self.output_path, 'detections', subdirectory_name, self.convertNameToFileName(object['name'], object['tags']['product']))
            output_folder = pathlib.Path(self.output_path)/'detections'/subdirectory_name
            #make sure the output folder exists for this detection
            output_folder.mkdir(exist_ok=True)

            YmlWriter.writeYmlFile(file_path, object)
            print("Successfully created detection " + file_path)
        
        elif type == NewContentType.story:
            file_path = os.path.join(self.output_path, 'stories', self.convertNameToFileName(object['name'], object['tags']['product']))
            YmlWriter.writeYmlFile(file_path, object)
            print("Successfully created story " + file_path)        
        
        else:
            raise(Exception(f"Object Must be Story or Detection, but is not: {object}"))



    def convertNameToFileName(self, name: str, product: list):
        file_name = name \
            .replace(' ', '_') \
            .replace('-','_') \
            .replace('.','_') \
            .replace('/','_') \
            .lower()
        if 'Splunk Behavioral Analytics' in product:
            
            file_name = 'ssa___' + file_name + '.yml'
        else:
            file_name = file_name + '.yml'
        return file_name


    def convertNameToTestFileName(self, name: str, product: list):
        file_name = name \
            .replace(' ', '_') \
            .replace('-','_') \
            .replace('.','_') \
            .replace('/','_') \
            .lower()
        if 'Splunk Behavioral Analytics' in product:          
            file_name = 'ssa___' + file_name + '.test.yml'
        else:
            file_name = file_name + '.test.yml'
        return file_name