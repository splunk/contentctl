import sys
import pathlib
from pydantic import ValidationError

from contentctl.objects.security_content_object import SecurityContentObject
from contentctl.input.yml_reader import YmlReader
from contentctl.objects.enums import SecurityContentType
from contentctl.objects.deployment import Deployment
from contentctl.objects.macro import Macro
from contentctl.objects.lookup import Lookup
from contentctl.objects.playbook import Playbook
from contentctl.objects.unit_test import UnitTest


class BasicBuilder():
    security_content_obj : SecurityContentObject


    def setObject(self, path: pathlib.Path, type: SecurityContentType) -> None:
        #print(path)
        yml_dict = YmlReader.load_file(path)
        if type == SecurityContentType.deployments:
            if "alert_action" in yml_dict:
                alert_action_dict = yml_dict["alert_action"]
                for key in alert_action_dict.keys():
                    yml_dict[key] = yml_dict["alert_action"][key]
            try:
                self.security_content_obj = Deployment.parse_obj(yml_dict)
            except ValidationError as e:
                print('Validation Error for file ' + str(path))
                print(e)
                sys.exit(1)
        elif type == SecurityContentType.macros:
            try:
                self.security_content_obj = Macro.parse_obj(yml_dict)
            except ValidationError as e:
                print('Validation Error for file ' + str(path))
                print(e)
                sys.exit(1)
        elif type == SecurityContentType.lookups:
            try:
                self.security_content_obj = Lookup.parse_obj(yml_dict)
            except ValidationError as e:
                print('Validation Error for file ' + str(path))
                print(e)
                sys.exit(1)
        elif type == SecurityContentType.unit_tests:
            try:
                self.security_content_obj = UnitTest.parse_obj(yml_dict)
            except ValidationError as e:
                print('Validation Error for file ' + str(path))
                print(e)
                sys.exit(1)
    
    def reset(self) -> None:
        self.security_content_obj = None

    def getObject(self) -> SecurityContentObject:
        return self.security_content_obj