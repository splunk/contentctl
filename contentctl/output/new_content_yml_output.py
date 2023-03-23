import os

from contentctl.objects.enums import SecurityContentType
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