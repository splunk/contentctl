import os
import uuid
import questionary
from dataclasses import dataclass
from datetime import datetime

from contentctl.objects.enums import SecurityContentType
from contentctl.input.new_content_questions import NewContentQuestions


@dataclass(frozen=True)
class NewContentGeneratorInputDto:
    type: SecurityContentType
    

@dataclass(frozen=True)
class NewContentGeneratorOutputDto:
    obj: dict
    answers: dict


class NewContentGenerator():

    
    def __init__(self, output_dto: NewContentGeneratorOutputDto) -> None:
        self.output_dto = output_dto


    def execute(self, input_dto: NewContentGeneratorInputDto) -> None:
        if input_dto.type == SecurityContentType.detections:
            questions = NewContentQuestions.get_questions_detection()
            answers = questionary.prompt(questions)
            self.output_dto.answers.update(answers)
            self.output_dto.obj['name'] = answers['detection_name']
            self.output_dto.obj['id'] = str(uuid.uuid4())
            self.output_dto.obj['version'] = 1
            self.output_dto.obj['date'] = datetime.today().strftime('%Y-%m-%d')
            self.output_dto.obj['author'] = answers['detection_author']
            self.output_dto.obj['data_source'] = answers['data_source']
            self.output_dto.obj['type'] = answers['detection_type']
            self.output_dto.obj['status'] = "production" #start everything as production since that's what we INTEND the content to become   
            self.output_dto.obj['description'] = 'UPDATE_DESCRIPTION'   
            file_name = self.output_dto.obj['name'].replace(' ', '_').replace('-','_').replace('.','_').replace('/','_').lower()
            self.output_dto.obj['search'] = answers['detection_search'] + ' | `' + file_name + '_filter`'
            self.output_dto.obj['how_to_implement'] = 'UPDATE_HOW_TO_IMPLEMENT'
            self.output_dto.obj['known_false_positives'] = 'UPDATE_KNOWN_FALSE_POSITIVES'            
            self.output_dto.obj['references'] = ['REFERENCE']
            self.output_dto.obj['tags'] = dict()
            self.output_dto.obj['tags']['analytic_story'] = ['UPDATE_STORY_NAME']
            self.output_dto.obj['tags']['asset_type'] = 'UPDATE asset_type'
            self.output_dto.obj['tags']['confidence'] = 'UPDATE value between 1-100'
            self.output_dto.obj['tags']['impact'] = 'UPDATE value between 1-100'
            self.output_dto.obj['tags']['message'] = 'UPDATE message'
            self.output_dto.obj['tags']['mitre_attack_id'] = [x.strip() for x in answers['mitre_attack_ids'].split(',')]
            self.output_dto.obj['tags']['observable'] = [{'name': 'UPDATE', 'type': 'UPDATE', 'role': ['UPDATE']}]
            self.output_dto.obj['tags']['product'] = ['Splunk Enterprise','Splunk Enterprise Security','Splunk Cloud']
            self.output_dto.obj['tags']['required_fields'] = ['UPDATE']
            self.output_dto.obj['tags']['risk_score'] = 'UPDATE (impact * confidence)/100'
            self.output_dto.obj['tags']['security_domain'] = answers['security_domain']
            self.output_dto.obj['tags']['cve'] = ['UPDATE WITH CVE(S) IF APPLICABLE']
            
            #generate the tests section
            self.output_dto.obj['tests'] = [
                {
                    'name': "True Positive Test",
                    'attack_data': [ 
                        {
                        'data': "Enter URL for Dataset Here.  This may also be a relative or absolute path on your local system for testing.",
                        "sourcetype": "UPDATE SOURCETYPE",
                        "source": "UPDATE SOURCE"
                        }
                    ]
                }
            ]
            
        

        elif input_dto.type == SecurityContentType.stories:
            questions = NewContentQuestions.get_questions_story()
            answers = questionary.prompt(questions)
            self.output_dto.answers.update(answers)
            self.output_dto.obj['name'] = answers['story_name']
            self.output_dto.obj['id'] = str(uuid.uuid4())
            self.output_dto.obj['version'] = 1
            self.output_dto.obj['date'] = datetime.today().strftime('%Y-%m-%d')
            self.output_dto.obj['author'] = answers['story_author']
            self.output_dto.obj['description'] = 'UPDATE_DESCRIPTION'
            self.output_dto.obj['narrative'] = 'UPDATE_NARRATIVE'
            self.output_dto.obj['references'] = []
            self.output_dto.obj['tags'] = dict()
            self.output_dto.obj['tags']['analytic_story'] = self.output_dto.obj['name']
            self.output_dto.obj['tags']['category'] = answers['category']
            self.output_dto.obj['tags']['product'] = ['Splunk Enterprise','Splunk Enterprise Security','Splunk Cloud']
            self.output_dto.obj['tags']['usecase'] = answers['usecase']
            self.output_dto.obj['tags']['cve'] = ['UPDATE WITH CVE(S) IF APPLICABLE']