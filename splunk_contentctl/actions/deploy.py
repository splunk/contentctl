import os
import sys
import json
import requests
from requests.auth import HTTPBasicAuth

from dataclasses import dataclass
from configparser import RawConfigParser
import splunklib.client as client

from splunk_contentctl.objects.config import Config


@dataclass(frozen=True)
class DeployInputDto:
    path: str
    config: Config


class Deploy:

    def execute(self, input_dto: DeployInputDto) -> None:

            splunk_args = {
                'host': input_dto.config.deploy.server,
                'port': 8089,
                'username': input_dto.config.deploy.username,
                'password': input_dto.config.deploy.password,
                'owner': 'nobody',
                'app': input_dto.config.deploy.app
            }
            service = client.connect(**splunk_args)

            macros_parser = RawConfigParser()
            macros_parser.read(os.path.join(input_dto.path, input_dto.config.build.splunk_app.path, "default", "macros.conf"))

            for section in macros_parser.sections():
                service.post('properties/macros', __stanza=section)
                service.post('properties/macros/' + section, **macros_parser[section])
                print("Deployed macro: " + section)
                
            detection_parser = RawConfigParser()
            detection_parser.read(os.path.join(input_dto.path, input_dto.config.build.splunk_app.path, "default", "savedsearches.conf"))

            try:
                service.delete('saved/searches/MSCA - Anomalous usage of 7zip - Rule')
            except Exception as e:
                pass

            for section in detection_parser.sections():
                if section.startswith(input_dto.config.build.splunk_app.prefix):
                    params = detection_parser[section]
                    params["name"] = section
                    response_actions = []
                    if input_dto.config.detection_configuration.notable and input_dto.config.detection_configuration.notable.rule_description:
                        response_actions.append('notable')
                    if input_dto.config.detection_configuration.rba and input_dto.config.detection_configuration.rba.enabled:
                        response_actions.append('risk')
                    params["actions"] = ','.join(response_actions)
                    params["request.ui_dispatch_app"] = "ES Content Updates"
                    params["request.ui_dispatch_view"] = "ES Content Updates"
                    params["alert_type"] = params.pop("counttype")
                    params["alert_comparator"] = params.pop("relation")
                    params["alert_threshold"] = params.pop("quantity")
                    params.pop("enablesched")
                
                    service.post('saved/searches', **params)

                    print("Deployed detection: " + params["name"])

            # story_parser = RawConfigParser()
            # story_parser.read(os.path.join(input_dto.path, input_dto.config.build.splunk_app.path, "default", "analyticstories.conf"))

            # for section in story_parser.sections():
            #     if section.startswith("analytic_story"):
            #         params = story_parser[section]
            #         params = dict(params.items())
            #         params["spec_version"] = 1
            #         params["version"] = 1
            #         name = section[17:]
            #         #service.post('services/analyticstories/configs/analytic_story', name=name, content=json.dumps(params))

            #         url = "https://3.72.220.157:8089/services/analyticstories/configs/analytic_story"
            #         data = dict()
            #         data["name"] = name
            #         data["content"] = params
            #         print(json.dumps(data))
            #         response = requests.post(
            #             url,
            #             auth=HTTPBasicAuth('admin', 'fgWFshd0mm7eErMj9qX'),
            #             data=json.dumps(data), 
            #             verify=False
            #         )
            #         print(response.text)