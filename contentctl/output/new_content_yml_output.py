import os
from contentctl.input.detection_builder import DetectionBuilder
from contentctl.objects.detection import Detection

from contentctl.objects.enums import SecurityContentType
from contentctl.objects.macro import Macro
from contentctl.output.yml_writer import YmlWriter


class NewContentYmlOutput():
    output_path: str
    
    def __init__(self, output_path:str):
        self.output_path = output_path
    
    
    def writeObjectNewContent(self, object: dict, type: SecurityContentType) -> None:
        if type == SecurityContentType.detections:
            file_path = os.path.join(self.output_path, 'detections', self.convertNameToFileName(object['name'], object['tags']['product']))
            test_obj = {}
            test_obj['name'] = object['name'] + ' Unit Test'
            test_obj['tests'] = [
                {
                    'name': object['name'],
                    'file': self.convertNameToFileName(object['name'],object['tags']['product']),
                    'pass_condition': '| stats count | where count > 0',
                    'earliest_time': '-24h',
                    'latest_time': 'now',
                    'attack_data': [
                        {
                            'file_name': 'UPDATE',
                            'data': 'UPDATE',
                            'source': 'UPDATE',
                            'sourcetype': 'UPDATE',
                            'update_timestamp': True
                        }
                    ]
                }
            ]

            macro_name = self.sanitize_name(object['name'], object['tags']['product']) + '_filter'
            macro_obj = Macro(
                name=macro_name,
                definition='search *',
                author=object['author'],
                date=object['date'],
                version=object['version'],
                description='Update this macro to limit the output results to filter out false positives.',
            ).dict(exclude_unset=True)
            file_path_macro = os.path.join(self.output_path, 'macros', macro_name + '.yml')

            YmlWriter.writeYmlFile(file_path_macro, macro_obj)
            file_path_test = os.path.join(self.output_path, 'tests', self.convertNameToTestFileName(object['name'], object['tags']['product']))
            YmlWriter.writeYmlFile(file_path_test, test_obj)
            #object.pop('source')
            YmlWriter.writeYmlFile(file_path, object)
            print("Successfully created detection " + file_path)
        
        elif type == SecurityContentType.stories:
            file_path = os.path.join(self.output_path, 'stories', self.convertNameToFileName(object['name'], object['tags']['product']))
            YmlWriter.writeYmlFile(file_path, object)
            print("Successfully created story " + file_path)        
        
        else:
            raise(Exception(f"Object Must be Story or Detection, but is not: {object}"))


    def sanitize_name(self, name: str, product: list) -> str:
        if 'Splunk Behavioral Analytics' in product:
            prefix = 'ssa___'
        else:
            prefix = ''

        return prefix + name \
            .replace(' ', '_') \
            .replace('-','_') \
            .replace('.','_') \
            .replace('/','_') \
            .lower()

    def convertNameToFileName(self, name: str, product: list):
        file_name = self.sanitize_name(name, product)
        file_name = file_name + '.yml'
        return file_name

    def convertNameToTestFileName(self, name: str, product: list):
        file_name = self.sanitize_name(name, product)
        file_name = file_name + '.test.yml'
        return file_name
