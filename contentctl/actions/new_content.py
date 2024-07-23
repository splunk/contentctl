

from dataclasses import dataclass
import questionary
from typing import Any
from contentctl.input.new_content_questions import NewContentQuestions
from contentctl.output.new_content_yml_output import NewContentYmlOutput
from contentctl.objects.config import new, NewContentType
import uuid
from datetime import datetime
import pathlib
from contentctl.objects.abstract_security_content_objects.security_content_object_abstract import SecurityContentObject_Abstract
from contentctl.output.yml_writer import YmlWriter

class NewContent:

    def buildDetection(self)->dict[str,Any]:
        questions = NewContentQuestions.get_questions_detection()
        answers = questionary.prompt(questions)
        answers.update(answers)
        answers['name'] = answers['detection_name']
        del answers['detection_name']
        answers['id'] = str(uuid.uuid4())
        answers['version'] = 1
        answers['date'] = datetime.today().strftime('%Y-%m-%d')
        answers['author'] = answers['detection_author']
        del answers['detection_author']
        answers['data_sources'] = answers['data_source']
        del answers['data_source']
        answers['type'] = answers['detection_type']
        del answers['detection_type']
        answers['status'] = "production" #start everything as production since that's what we INTEND the content to become   
        answers['description'] = 'UPDATE_DESCRIPTION'   
        file_name = answers['name'].replace(' ', '_').replace('-','_').replace('.','_').replace('/','_').lower()
        answers['search'] = answers['detection_search'] + ' | `' + file_name + '_filter`'
        del answers['detection_search']
        answers['how_to_implement'] = 'UPDATE_HOW_TO_IMPLEMENT'
        answers['known_false_positives'] = 'UPDATE_KNOWN_FALSE_POSITIVES'            
        answers['references'] = ['REFERENCE']
        answers['tags'] = dict()
        answers['tags']['analytic_story'] = ['UPDATE_STORY_NAME']
        answers['tags']['asset_type'] = 'UPDATE asset_type'
        answers['tags']['confidence'] = 'UPDATE value between 1-100'
        answers['tags']['impact'] = 'UPDATE value between 1-100'
        answers['tags']['message'] = 'UPDATE message'
        answers['tags']['mitre_attack_id'] = [x.strip() for x in answers['mitre_attack_ids'].split(',')]
        answers['tags']['observable'] = [{'name': 'UPDATE', 'type': 'UPDATE', 'role': ['UPDATE']}]
        answers['tags']['product'] = ['Splunk Enterprise','Splunk Enterprise Security','Splunk Cloud']
        answers['tags']['required_fields'] = ['UPDATE']
        answers['tags']['risk_score'] = 'UPDATE (impact * confidence)/100'
        answers['tags']['security_domain'] = answers['security_domain']
        del answers["security_domain"]
        answers['tags']['cve'] = ['UPDATE WITH CVE(S) IF APPLICABLE']
        
        #generate the tests section
        answers['tests'] = [
            {
                'name': "True Positive Test",
                'attack_data': [ 
                    {
                    'data': "https://github.com/splunk/contentctl/wiki",
                    "sourcetype": "UPDATE SOURCETYPE",
                    "source": "UPDATE SOURCE"
                    }
                ]
            }
        ]
        del answers["mitre_attack_ids"]
        return answers

    def buildStory(self)->dict[str,Any]:
        questions = NewContentQuestions.get_questions_story()
        answers = questionary.prompt(questions)
        answers['name'] = answers['story_name']
        del answers['story_name']
        answers['id'] = str(uuid.uuid4())
        answers['version'] = 1
        answers['date'] = datetime.today().strftime('%Y-%m-%d')
        answers['author'] = answers['story_author']
        del answers['story_author']
        answers['description'] = 'UPDATE_DESCRIPTION'
        answers['narrative'] = 'UPDATE_NARRATIVE'
        answers['references'] = []
        answers['tags'] = dict()
        answers['tags']['category'] = answers['category']
        del answers['category']
        answers['tags']['product'] = ['Splunk Enterprise','Splunk Enterprise Security','Splunk Cloud']
        answers['tags']['usecase'] = answers['usecase']
        del answers['usecase']
        answers['tags']['cve'] = ['UPDATE WITH CVE(S) IF APPLICABLE']
        return answers
    

    def execute(self, input_dto: new) -> None:
        if input_dto.type == NewContentType.detection:
            content_dict = self.buildDetection()
            subdirectory = pathlib.Path('detections') / content_dict.pop('detection_kind')
        elif input_dto.type == NewContentType.story:
            content_dict = self.buildStory()
            subdirectory = pathlib.Path('stories')
        else:
            raise Exception(f"Unsupported new content type: [{input_dto.type}]")

        full_output_path = input_dto.path / subdirectory / SecurityContentObject_Abstract.contentNameToFileName(content_dict.get('name'))
        YmlWriter.writeYmlFile(str(full_output_path), content_dict)



    def writeObjectNewContent(self, object: dict, subdirectory_name: str, type: NewContentType) -> None:
        if type == NewContentType.detection:
            file_path = os.path.join(self.output_path, 'detections', subdirectory_name, self.convertNameToFileName(object['name'], object['tags']['product']))
            output_folder = pathlib.Path(self.output_path)/'detections'/subdirectory_name
            #make sure the output folder exists for this detection
            output_folder.mkdir(exist_ok=True)

            YmlWriter.writeDetection(file_path, object)
            print("Successfully created detection " + file_path)
        
        elif type == NewContentType.story:
            file_path = os.path.join(self.output_path, 'stories', self.convertNameToFileName(object['name'], object['tags']['product']))
            YmlWriter.writeStory(file_path, object)
            print("Successfully created story " + file_path)        
        
        else:
            raise(Exception(f"Object Must be Story or Detection, but is not: {object}"))

