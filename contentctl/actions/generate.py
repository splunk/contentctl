import sys
import shutil
import os

from dataclasses import dataclass

from contentctl.objects.enums import SecurityContentProduct, SecurityContentType
from contentctl.input.director import Director, DirectorInputDto, DirectorOutputDto
from contentctl.output.conf_output import ConfOutput
from contentctl.output.ba_yml_output import BAYmlOutput
from contentctl.output.api_json_output import ApiJsonOutput
import pathlib
import json
import datetime
from typing import Union

@dataclass(frozen=True)
class GenerateInputDto:
    director_input_dto: DirectorInputDto
    appinspect_api_username: Union[str,None] = None
    appinspect_api_password: Union[str,None] = None


class Generate:

    def execute(self, input_dto: GenerateInputDto) -> DirectorOutputDto:
        director_output_dto = DirectorOutputDto([],[],[],[],[],[],[],[],[])
        director = Director(director_output_dto)
        director.execute(input_dto.director_input_dto)

        if input_dto.director_input_dto.product == SecurityContentProduct.SPLUNK_APP:
            if input_dto.appinspect_api_username and input_dto.appinspect_api_password:
                pass
            elif input_dto.appinspect_api_username or input_dto.appinspect_api_password:
                if input_dto.appinspect_api_password:
                    raise Exception("appinspect_api_password was provided, but appinspect_api_username was not. Please provide both or neither")
                else:
                    raise Exception("appinspect_api_username was provided, but appinspect_api_password was not. Please provide both or neither")            
            
            conf_output = ConfOutput(input_dto.director_input_dto.input_path, input_dto.director_input_dto.config)
            conf_output.writeHeaders()
            conf_output.writeObjects(director_output_dto.detections, SecurityContentType.detections)
            conf_output.writeObjects(director_output_dto.stories, SecurityContentType.stories)
            conf_output.writeObjects(director_output_dto.baselines, SecurityContentType.baselines)
            conf_output.writeObjects(director_output_dto.investigations, SecurityContentType.investigations)
            conf_output.writeObjects(director_output_dto.lookups, SecurityContentType.lookups)
            conf_output.writeObjects(director_output_dto.macros, SecurityContentType.macros)
            conf_output.writeAppConf()
            conf_output.packageApp()

            conf_output.inspectAppCLI()
            if input_dto.appinspect_api_username and input_dto.appinspect_api_password:
                conf_output.inspectAppAPI(input_dto.appinspect_api_username, input_dto.appinspect_api_password)
            
            print(f'Generate of security content successful to {conf_output.output_path}')
            return director_output_dto

        elif input_dto.director_input_dto.product == SecurityContentProduct.SSA:
            output_path = os.path.join(input_dto.director_input_dto.input_path, input_dto.director_input_dto.config.build_ssa.path_root)
            shutil.rmtree(output_path + '/srs/', ignore_errors=True)
            shutil.rmtree(output_path + '/complex/', ignore_errors=True)
            os.makedirs(output_path + '/complex/')
            os.makedirs(output_path + '/srs/')     
            ba_yml_output = BAYmlOutput()
            ba_yml_output.writeObjects(director_output_dto.ssa_detections, output_path)

        elif input_dto.director_input_dto.product == SecurityContentProduct.API:
            output_path = os.path.join(input_dto.director_input_dto.input_path, input_dto.director_input_dto.config.build_api.path_root)
            shutil.rmtree(output_path, ignore_errors=True)
            os.makedirs(output_path)
            api_json_output = ApiJsonOutput()
            api_json_output.writeObjects(director_output_dto.detections, output_path, SecurityContentType.detections)
            api_json_output.writeObjects(director_output_dto.stories, output_path, SecurityContentType.stories)
            api_json_output.writeObjects(director_output_dto.baselines, output_path, SecurityContentType.baselines)
            api_json_output.writeObjects(director_output_dto.investigations, output_path, SecurityContentType.investigations)
            api_json_output.writeObjects(director_output_dto.lookups, output_path, SecurityContentType.lookups)
            api_json_output.writeObjects(director_output_dto.macros, output_path, SecurityContentType.macros)
            api_json_output.writeObjects(director_output_dto.deployments, output_path, SecurityContentType.deployments)
            # Ensure that the generated files are not too large
            api_json_output.checkMaxJsonObjectSize(output_path)
 
            #create version file for sse api
            version_file = pathlib.Path(output_path)/"version.json"
            utc_time = datetime.datetime.utcnow().replace(microsecond=0).isoformat()
            version_dict = {"version":{"name":f"v{input_dto.director_input_dto.config.build.version}","published_at": f"{utc_time}Z"  }}
            with open(version_file,"w") as version_f:
                json.dump(version_dict,version_f)
                
        return director_output_dto