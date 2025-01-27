import pathlib
import uuid
from datetime import datetime
from typing import Any

import questionary

from contentctl.input.new_content_questions import NewContentQuestions
from contentctl.objects.abstract_security_content_objects.security_content_object_abstract import (
    SecurityContentObject_Abstract,
)
from contentctl.objects.config import NewContentType, new
from contentctl.objects.enums import AssetType
from contentctl.output.yml_writer import YmlWriter


class NewContent:
    UPDATE_PREFIX = "__UPDATE__"

    DEFAULT_DRILLDOWN_DEF = [
        {
            "name": f'View the detection results for - "${UPDATE_PREFIX}FIRST_RISK_OBJECT$" and "${UPDATE_PREFIX}SECOND_RISK_OBJECT$"',
            "search": f'%original_detection_search% | search  "${UPDATE_PREFIX}FIRST_RISK_OBJECT = "${UPDATE_PREFIX}FIRST_RISK_OBJECT$" second_observable_type_here = "${UPDATE_PREFIX}SECOND_RISK_OBJECT$"',
            "earliest_offset": "$info_min_time$",
            "latest_offset": "$info_max_time$",
        },
        {
            "name": f'View risk events for the last 7 days for - "${UPDATE_PREFIX}FIRST_RISK_OBJECT$" and "${UPDATE_PREFIX}SECOND_RISK_OBJECT$"',
            "search": f'| from datamodel Risk.All_Risk | search normalized_risk_object IN ("${UPDATE_PREFIX}FIRST_RISK_OBJECT$", "${UPDATE_PREFIX}SECOND_RISK_OBJECT$") starthoursago=168  | stats count min(_time) as firstTime max(_time) as lastTime values(search_name) as "Search Name" values(risk_message) as "Risk Message" values(analyticstories) as "Analytic Stories" values(annotations._all) as "Annotations" values(annotations.mitre_attack.mitre_tactic) as "ATT&CK Tactics" by normalized_risk_object | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`',
            "earliest_offset": "$info_min_time$",
            "latest_offset": "$info_max_time$",
        },
    ]

    DEFAULT_RBA = {
        "message": "Risk Message goes here",
        "risk_objects": [{"field": "dest", "type": "system", "score": 10}],
        "threat_objects": [
            {"field": "parent_process_name", "type": "parent_process_name"}
        ],
    }

    def buildDetection(self) -> tuple[dict[str, Any], str]:
        questions = NewContentQuestions.get_questions_detection()
        answers: dict[str, str] = questionary.prompt(
            questions,
            kbi_msg="User did not answer all of the prompt questions. Exiting...",
        )
        if not answers:
            raise ValueError("User didn't answer one or more questions!")

        data_source_field = (
            answers["data_sources"]
            if len(answers["data_sources"]) > 0
            else [f"{NewContent.UPDATE_PREFIX} zero or more data_sources"]
        )
        file_name = (
            answers["detection_name"]
            .replace(" ", "_")
            .replace("-", "_")
            .replace(".", "_")
            .replace("/", "_")
            .lower()
        )

        # Minimum lenght for a mitre tactic is 5 characters: T1000
        if len(answers["mitre_attack_ids"]) >= 5:
            mitre_attack_ids = [
                x.strip() for x in answers["mitre_attack_ids"].split(",")
            ]
        else:
            # string was too short, so just put a placeholder
            mitre_attack_ids = [
                f"{NewContent.UPDATE_PREFIX} zero or more mitre_attack_ids"
            ]

        output_file_answers: dict[str, Any] = {
            "name": answers["detection_name"],
            "id": str(uuid.uuid4()),
            "version": 1,
            "date": datetime.today().strftime("%Y-%m-%d"),
            "author": answers["detection_author"],
            "status": "production",  # start everything as production since that's what we INTEND the content to become
            "type": answers["detection_type"],
            "description": f"{NewContent.UPDATE_PREFIX} by providing a description of your search",
            "data_source": data_source_field,
            "search": f"{answers['detection_search']} | `{file_name}_filter`",
            "how_to_implement": f"{NewContent.UPDATE_PREFIX} how to implement your search",
            "known_false_positives": f"{NewContent.UPDATE_PREFIX} known false positives for your search",
            "references": [
                f"{NewContent.UPDATE_PREFIX} zero or more http references to provide more information about your search"
            ],
            "drilldown_searches": NewContent.DEFAULT_DRILLDOWN_DEF,
            "rba": NewContent.DEFAULT_RBA,
            "tags": {
                "analytic_story": [
                    f"{NewContent.UPDATE_PREFIX} by providing zero or more analytic stories"
                ],
                "asset_type": f"{NewContent.UPDATE_PREFIX} by providing and asset type from {list(AssetType._value2member_map_)}",
                "mitre_attack_id": mitre_attack_ids,
                "product": [
                    "Splunk Enterprise",
                    "Splunk Enterprise Security",
                    "Splunk Cloud",
                ],
                "security_domain": answers["security_domain"],
                "cve": [f"{NewContent.UPDATE_PREFIX} with CVE(s) if applicable"],
            },
            "tests": [
                {
                    "name": "True Positive Test",
                    "attack_data": [
                        {
                            "data": f"{NewContent.UPDATE_PREFIX} the data file to replay. Go to https://github.com/splunk/contentctl/wiki for information about the format of this field",
                            "sourcetype": f"{NewContent.UPDATE_PREFIX} the sourcetype of your data file.",
                            "source": f"{NewContent.UPDATE_PREFIX} the source of your datafile",
                        }
                    ],
                }
            ],
        }

        if answers["detection_type"] not in ["TTP", "Anomaly", "Correlation"]:
            del output_file_answers["drilldown_searches"]

        if answers["detection_type"] not in ["TTP", "Anomaly"]:
            del output_file_answers["rba"]

        return output_file_answers, answers["detection_kind"]

    def buildStory(self) -> dict[str, Any]:
        questions = NewContentQuestions.get_questions_story()
        answers = questionary.prompt(
            questions,
            kbi_msg="User did not answer all of the prompt questions. Exiting...",
        )
        if not answers:
            raise ValueError("User didn't answer one or more questions!")
        answers["name"] = answers["story_name"]
        del answers["story_name"]
        answers["id"] = str(uuid.uuid4())
        answers["version"] = 1
        answers["status"] = "production"
        answers["date"] = datetime.today().strftime("%Y-%m-%d")
        answers["author"] = answers["story_author"]
        del answers["story_author"]
        answers["description"] = "UPDATE_DESCRIPTION"
        answers["narrative"] = "UPDATE_NARRATIVE"
        answers["references"] = []
        answers["tags"] = dict()
        answers["tags"]["category"] = answers["category"]
        del answers["category"]
        answers["tags"]["product"] = [
            "Splunk Enterprise",
            "Splunk Enterprise Security",
            "Splunk Cloud",
        ]
        answers["tags"]["usecase"] = answers["usecase"]
        del answers["usecase"]
        answers["tags"]["cve"] = ["UPDATE WITH CVE(S) IF APPLICABLE"]
        return answers

    def execute(self, input_dto: new) -> None:
        if input_dto.type == NewContentType.detection:
            content_dict, detection_kind = self.buildDetection()
            subdirectory = pathlib.Path("detections") / detection_kind
        elif input_dto.type == NewContentType.story:
            content_dict = self.buildStory()
            subdirectory = pathlib.Path("stories")
        else:
            raise Exception(f"Unsupported new content type: [{input_dto.type}]")

        full_output_path = (
            input_dto.path
            / subdirectory
            / SecurityContentObject_Abstract.contentNameToFileName(
                content_dict.get("name")
            )
        )
        YmlWriter.writeYmlFile(str(full_output_path), content_dict)
