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
    DEFAULT_DRILLDOWN_DEF = [
        {
            "name": 'View the detection results for - "$first_observable_name_here$" and "$second_observable_name_here$"',
            "search": '%original_detection_search% | search  first_observable_type_here = "$first_observable_name_here$" second_observable_type_here = $second_observable_name_here$',
            "earliest_offset": '$info_min_time$',
            "latest_offset": '$info_max_time$' 
        },
        {
            "name": 'View risk events for the last 7 days for - "$first_observable_name_here$" and "$second_observable_name_here$"',
            "search": '| from datamodel Risk.All_Risk | search normalized_risk_object IN ("$first_observable_name_here$", "$second_observable_name_here$") starthoursago=168  | stats count min(_time) as firstTime max(_time) as lastTime values(search_name) as "Search Name" values(risk_message) as "Risk Message" values(analyticstories) as "Analytic Stories" values(annotations._all) as "Annotations" values(annotations.mitre_attack.mitre_tactic) as "ATT&CK Tactics" by normalized_risk_object | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`',
            "earliest_offset": '$info_min_time$',
            "latest_offset": '$info_max_time$' 
        }
    ]

    def buildDetection(self) -> tuple[dict[str, Any], str]:
        questions = NewContentQuestions.get_questions_detection()
        answers: dict[str, str] = questionary.prompt(
            questions,
            kbi_msg="User did not answer all of the prompt questions. Exiting...",
        )
        if not answers:
            raise ValueError("User didn't answer one or more questions!")

        data_source_field = (
            answers["data_source"] if len(answers["data_source"]) > 0 else ["UPDATE"]
        )
        file_name = (
            answers["detection_name"]
            .replace(" ", "_")
            .replace("-", "_")
            .replace(".", "_")
            .replace("/", "_")
            .lower()
        )

        #Minimum lenght for a mitre tactic is 5 characters: T1000
        if len(answers["mitre_attack_ids"]) >= 5:
            mitre_attack_ids = [x.strip() for x in answers["mitre_attack_ids"].split(",")]
        else:
            #string was too short, so just put a placeholder
            mitre_attack_ids = ["UPDATE"]

        output_file_answers: dict[str, Any] = {
            "name": answers["detection_name"],
            "id": str(uuid.uuid4()),
            "version": 1,
            "date": datetime.today().strftime("%Y-%m-%d"),
            "author": answers["detection_author"],
            "status": "production",  # start everything as production since that's what we INTEND the content to become
            "type": answers["detection_type"],
            "description": "UPDATE_DESCRIPTION",
            "data_source": data_source_field,
            "search": f"{answers['detection_search']} | `{file_name}_filter`'",
            "how_to_implement": "UPDATE_HOW_TO_IMPLEMENT",
            "known_false_positives": "UPDATE_KNOWN_FALSE_POSITIVES",
            "references": ["REFERENCE"],
            "drilldown_searches": NewContent.DEFAULT_DRILLDOWN_DEF,
            "tags": {
                "analytic_story": ["UPDATE_STORY_NAME"],
                "asset_type": "UPDATE asset_type",
                "confidence": "UPDATE value between 1-100",
                "impact": "UPDATE value between 1-100",
                "message": "UPDATE message",
                "mitre_attack_id": mitre_attack_ids,
                "observable": [
                    {"name": "UPDATE", "type": "UPDATE", "role": ["UPDATE"]}
                ],
                "product": [
                    "Splunk Enterprise",
                    "Splunk Enterprise Security",
                    "Splunk Cloud",
                ],
                "security_domain": answers["security_domain"],
                "cve": ["UPDATE WITH CVE(S) IF APPLICABLE"],
            },
            "tests": [
                {
                    "name": "True Positive Test",
                    "attack_data": [
                        {
                            "data": "Go to https://github.com/splunk/contentctl/wiki for information about the format of this field",
                            "sourcetype": "UPDATE SOURCETYPE",
                            "source": "UPDATE SOURCE",
                        }
                    ],
                }
            ],
        }

        if answers["detection_type"] not in ["TTP", "Correlation", "Anomaly", "TTP"]:
            del output_file_answers["drilldown_searches"]

        return output_file_answers, answers['detection_kind']

    def buildStory(self) -> dict[str, Any]:
        questions = NewContentQuestions.get_questions_story()
        answers = questionary.prompt(
            questions, 
            kbi_msg="User did not answer all of the prompt questions. Exiting...")
        if not answers:
            raise ValueError("User didn't answer one or more questions!")
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
            content_dict, detection_kind = self.buildDetection()
            subdirectory = pathlib.Path('detections') / detection_kind
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
            # make sure the output folder exists for this detection
            output_folder.mkdir(exist_ok=True)

            YmlWriter.writeDetection(file_path, object)
            print("Successfully created detection " + file_path)

        elif type == NewContentType.story:
            file_path = os.path.join(self.output_path, 'stories', self.convertNameToFileName(object['name'], object['tags']['product']))
            YmlWriter.writeStory(file_path, object)
            print("Successfully created story " + file_path)        

        else:
            raise(Exception(f"Object Must be Story or Detection, but is not: {object}"))
