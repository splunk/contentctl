import os
import sys
import json
import requests
from requests.auth import HTTPBasicAuth

from dataclasses import dataclass
from configparser import RawConfigParser
import splunklib.client as client

from contentctl.objects.config import Config
import pathlib

@dataclass(frozen=True)
class API_DeployInputDto:
    path: pathlib.Path
    config: Config


class API_Deploy:
    def fix_newlines_in_conf_files(self, conf_path: pathlib.Path) -> RawConfigParser:
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

    def execute(self, input_dto: API_DeployInputDto) -> None:
        if len(input_dto.config.deployments.rest_api_deployments) == 0:
            raise Exception("No rest_api_deployments defined in 'contentctl.yml'")
        app_path =  pathlib.Path(input_dto.config.build.path_root)/input_dto.config.build.name
        if not app_path.is_dir():
            raise Exception(f"The unpackaged app does not exist at the path {app_path}. Please run 'contentctl build' to generate the app.")
        for target in input_dto.config.deployments.rest_api_deployments:
            print(f"Deploying '{input_dto.config.build.name}' to target '{target.server}' [{target.description}]")
            splunk_args = {
                "host": target.server,
                "port": target.port,
                "username": target.username,
                "password": target.password,
                "owner": "nobody",
                "app": "search",
            }
            print("Warning - we are currently deploying all content into the 'search' app. "
                  "At this time, this means the user does not have to install the app "
                  "manually, but this will change")
            service = client.connect(**splunk_args)

                
            macros_parser = self.fix_newlines_in_conf_files(
                app_path/"default"/"macros.conf"
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
                    tqdm.tqdm.write(f"Deployed macro [{section}]")
                except Exception as e:
                    tqdm.tqdm.write(f"Error deploying macro {section}: {str(e)}")

            detection_parser = RawConfigParser()
            detection_parser = self.fix_newlines_in_conf_files(
                app_path/"default"/"savedsearches.conf",
            )
            

            for section in tqdm.tqdm(
                detection_parser.sections(), bar_format=bar_format_detections
            ):
                try:
                    if section.startswith(input_dto.config.build.prefix):
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
                        
                        try:
                            service.saved_searches.delete(section)
                            #tqdm.tqdm.write(f"Deleted old saved search: {section}")
                        except Exception as e:
                            #tqdm.tqdm.write(f"Error deleting savedsearch '{section}' :[{str(e)}]")
                            pass
                        
                        service.post("saved/searches", **params)
                        tqdm.tqdm.write(f"Deployed savedsearch [{section}]")
                
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
