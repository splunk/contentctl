import os
import sys
import json
import requests
from requests.auth import HTTPBasicAuth

from dataclasses import dataclass
from configparser import RawConfigParser
import splunklib.client as client

from contentctl.objects.config import Config


@dataclass(frozen=True)
class DeployInputDto:
    path: str
    config: Config


class Deploy:
    def fix_newlines_in_conf_files(self, conf_path: str) -> RawConfigParser:
        parser = RawConfigParser()
        with open(conf_path, "r") as conf_data_file:
            conf_data = conf_data_file.read()

        # ConfigParser cannot read multipleline strings that simply escape the newline character with \
        # To include a newline, you need to include a space at the beginning of the newline.
        # We will simply replace all \NEWLINE with NEWLINESPACE (removing the leading literal \).
        # We will discuss whether we intend to make these changes to the underlying conf files
        # or just apply the changes here
        conf_data = conf_data.replace("\\\n", "\n ")

        parser.read_string(conf_data)
        return parser

    def execute(self, input_dto: DeployInputDto) -> None:

        splunk_args = {
            "host": input_dto.config.deploy.server,
            "port": 8089,
            "username": input_dto.config.deploy.username,
            "password": input_dto.config.deploy.password,
            "owner": "nobody",
            "app": input_dto.config.deploy.app,
        }
        service = client.connect(**splunk_args)

        macros_parser = self.fix_newlines_in_conf_files(
            os.path.join(
                input_dto.path,
                input_dto.config.build.splunk_app.path,
                "default",
                "macros.conf",
            )
        )
        import tqdm

        bar_format_macros = (
            f"Deploying macros        "
            + "{percentage:3.0f}%[{bar:20}]"
            + "[{n_fmt}/{total_fmt} | ETA: {remaining}]"
        )
        bar_format_detections = (
            f"Deploying saved searches"
            + "{percentage:3.0f}%[{bar:20}]"
            + "[{n_fmt}/{total_fmt} | ETA: {remaining}]"
        )
        for section in tqdm.tqdm(
            macros_parser.sections(), bar_format=bar_format_macros
        ):
            try:
                service.post("properties/macros", __stanza=section)
                service.post("properties/macros/" + section, **macros_parser[section])
                # print("Deployed macro: " + section)
            except Exception as e:
                tqdm.tqdm.write(f"Error deploying macro {section}: {str(e)}")

        detection_parser = RawConfigParser()
        detection_parser = self.fix_newlines_in_conf_files(
            os.path.join(
                input_dto.path,
                input_dto.config.build.splunk_app.path,
                "default",
                "savedsearches.conf",
            )
        )
        try:
            service.delete("saved/searches/MSCA - Anomalous usage of 7zip - Rule")
        except Exception as e:
            pass

        for section in tqdm.tqdm(
            detection_parser.sections(), bar_format=bar_format_detections
        ):
            try:
                if section.startswith(input_dto.config.build.splunk_app.prefix):
                    params = detection_parser[section]
                    params["name"] = section
                    response_actions = []
                    if (
                        input_dto.config.detection_configuration.notable
                        and input_dto.config.detection_configuration.notable.rule_description
                    ):
                        response_actions.append("notable")
                    if (
                        input_dto.config.detection_configuration.rba
                        and input_dto.config.detection_configuration.rba.enabled
                    ):
                        response_actions.append("risk")
                    params["actions"] = ",".join(response_actions)
                    params["request.ui_dispatch_app"] = "ES Content Updates"
                    params["request.ui_dispatch_view"] = "ES Content Updates"
                    params["alert_type"] = params.pop("counttype")
                    params["alert_comparator"] = params.pop("relation")
                    params["alert_threshold"] = params.pop("quantity")
                    params.pop("enablesched")

                    service.post("saved/searches", **params)

                    # print("Deployed detection: " + params["name"])
            except Exception as e:
                tqdm.tqdm.write(f"Error deploying saved search {section}: {str(e)}")

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
