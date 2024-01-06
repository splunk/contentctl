import sys
import pathlib
from pydantic import ValidationError
    

from contentctl.objects.deployment import Deployment
from contentctl.objects.lookup import Lookup
from contentctl.objects.macro import Macro

from contentctl.input.yml_reader import YmlReader
from contentctl.objects.enums import SecurityContentType
from contentctl.objects.security_content_object import SecurityContentObject


from contentctl.objects.unit_test import UnitTest
from contentctl.input.director import DirectorOutputDto

class BasicBuilder():
    security_content_obj : SecurityContentObject


    def setObject(self, path: pathlib.Path, 
                  type: SecurityContentType,
                  output_dto:DirectorOutputDto) -> None:
        yml_dict = YmlReader.load_file(path)
        if type == SecurityContentType.deployments:
            if "alert_action" in yml_dict:
                alert_action_dict = yml_dict["alert_action"]
                for key in alert_action_dict.keys():
                    yml_dict[key] = yml_dict["alert_action"][key]
            self.security_content_obj = Deployment.model_validate(yml_dict, context={"output_dto":output_dto})
            
        elif type == SecurityContentType.macros:
            self.security_content_obj = Macro.model_validate(yml_dict, context={"output_dto":output_dto})
            
        elif type == SecurityContentType.lookups:
            self.security_content_obj = Lookup.model_validate(yml_dict, context={"output_dto":output_dto})
            
        elif type == SecurityContentType.unit_tests:
            self.security_content_obj = UnitTest.model_validate(yml_dict, context={"output_dto":output_dto})
            
    
    def reset(self) -> None:
        self.security_content_obj = None

    def getObject(self) -> SecurityContentObject:
        return self.security_content_obj