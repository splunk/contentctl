import sys

from pydantic import ValidationError

from splunk_contentctl.objects.security_content_object import SecurityContentObject
from splunk_contentctl.input.yml_reader import YmlReader
from splunk_contentctl.objects.enums import SecurityContentType
from splunk_contentctl.objects.deployment import Deployment
from splunk_contentctl.objects.macro import Macro
from splunk_contentctl.objects.lookup import Lookup
from splunk_contentctl.objects.playbook import Playbook
from splunk_contentctl.objects.unit_test import UnitTest


class BasicBuilder():
    security_content_obj : SecurityContentObject


    def setObject(self, path: str, type: SecurityContentType) -> None:
        yml_dict = YmlReader.load_file(path)
        if type == SecurityContentType.deployments:
            if "alert_action" in yml_dict:
                alert_action_dict = yml_dict["alert_action"]
                for key in alert_action_dict.keys():
                    yml_dict[key] = yml_dict["alert_action"][key]
            try:
                self.security_content_obj = Deployment.parse_obj(yml_dict)
            except ValidationError as e:
                print('Validation Error for file ' + path)
                print(e)
                sys.exit(1)
        elif type == SecurityContentType.macros:
            try:
                self.security_content_obj = Macro.parse_obj(yml_dict)
            except ValidationError as e:
                print('Validation Error for file ' + path)
                print(e)
                sys.exit(1)
        elif type == SecurityContentType.lookups:
            try:
                self.security_content_obj = Lookup.parse_obj(yml_dict)
            except ValidationError as e:
                print('Validation Error for file ' + path)
                print(e)
                sys.exit(1)
        elif type == SecurityContentType.unit_tests:
            try:
                self.security_content_obj = UnitTest.parse_obj(yml_dict)
            except ValidationError as e:
                print('Validation Error for file ' + path)
                print(e)
                sys.exit(1)
    
    def reset(self) -> None:
        self.security_content_obj = None

    def getObject(self) -> SecurityContentObject:
        return self.security_content_obj