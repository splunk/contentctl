import sys
import shutil
import os

from dataclasses import dataclass

from contentctl.objects.enums import SecurityContentProduct, SecurityContentType
from contentctl.input.director import Director, DirectorOutputDto
from contentctl.output.conf_output import ConfOutput
from contentctl.output.ba_yml_output import BAYmlOutput
from contentctl.output.api_json_output import ApiJsonOutput
import pathlib
import json
import datetime
from typing import Union

from contentctl.objects.config import build

@dataclass(frozen=True)
class BuildInputDto:
    director_output_dto: DirectorOutputDto
    config:build


class Build:

    def execute(self, input_dto: BuildInputDto) -> DirectorOutputDto:
        if input_dto.config.build_app or input_dto.config.build_api:    
            conf_output = ConfOutput(input_dto.config)
            conf_output.writeHeaders()
            conf_output.writeObjects(input_dto.director_output_dto.detections, SecurityContentType.detections)
            conf_output.writeObjects(input_dto.director_output_dto.stories, SecurityContentType.stories)
            conf_output.writeObjects(input_dto.director_output_dto.baselines, SecurityContentType.baselines)
            conf_output.writeObjects(input_dto.director_output_dto.investigations, SecurityContentType.investigations)
            conf_output.writeObjects(input_dto.director_output_dto.lookups, SecurityContentType.lookups)
            conf_output.writeObjects(input_dto.director_output_dto.macros, SecurityContentType.macros)
            conf_output.writeAppConf()
            conf_output.packageApp()

            
            print(f'Build of security content successful to {conf_output.config.getPackageFilePath()}')
            return input_dto.director_output_dto

        elif input_dto.config.build_api:    
            shutil.rmtree(input_dto.config.getAPIPath(), ignore_errors=True)
            input_dto.config.getAPIPath().mkdir(parents=True)
            api_json_output = ApiJsonOutput()
            for output_objects, output_type in [(input_dto.director_output_dto.detections, SecurityContentType.detections),
                                                (input_dto.director_output_dto.stories, SecurityContentType.stories),
                                                (input_dto.director_output_dto.baselines, SecurityContentType.baselines),
                                                (input_dto.director_output_dto.investigations, SecurityContentType.investigations),
                                                (input_dto.director_output_dto.lookups, SecurityContentType.lookups),
                                                (input_dto.director_output_dto.macros, SecurityContentType.macros),
                                                (input_dto.director_output_dto.deployments, SecurityContentType.deployments)]:
                api_json_output.writeObjects(output_objects, input_dto.config.getAPIPath(), output_type)
           
            
            #create version file for sse api
            version_file = input_dto.config.getAPIPath()/"version.json"
            utc_time = datetime.datetime.utcnow().replace(microsecond=0).isoformat()
            version_dict = {"version":{"name":f"v{input_dto.config.app.version}","published_at": f"{utc_time}Z"  }}
            with open(version_file,"w") as version_f:
                json.dump(version_dict,version_f)

        elif input_dto.config.build_ssa:
            
            srs_path = input_dto.config.getSSAPath() / 'srs'
            complex_path = input_dto.config.getSSAPath() / 'complex'
            shutil.rmtree(srs_path, ignore_errors=True)
            shutil.rmtree(complex_path, ignore_errors=True)
            srs_path.mkdir(parents=True)
            complex_path.mkdir(parents=True)
            ba_yml_output = BAYmlOutput()
            ba_yml_output.writeObjects(input_dto.director_output_dto.ssa_detections, srs_path)

        
                
        return input_dto.director_output_dto