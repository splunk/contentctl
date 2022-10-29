import sys
import shutil
import os

from dataclasses import dataclass

from splunk_contentctl.objects.enums import SecurityContentProduct, SecurityContentType
from splunk_contentctl.input.director import Director, DirectorInputDto, DirectorOutputDto
from splunk_contentctl.output.conf_output import ConfOutput
from splunk_contentctl.output.ba_yml_output import BAYmlOutput
from splunk_contentctl.output.api_json_output import ApiJsonOutput


@dataclass(frozen=True)
class GenerateInputDto:
    director_input_dto: DirectorInputDto
    product: SecurityContentProduct
    output_path : str


class Generate:

    def execute(self, input_dto: GenerateInputDto) -> None:
        director_output_dto = DirectorOutputDto([],[],[],[],[],[],[],[],[])
        director = Director(director_output_dto)
        director.execute(input_dto.director_input_dto)

        if input_dto.product == SecurityContentProduct.SPLUNK_ENTERPRISE_APP:
            conf_output = ConfOutput(input_dto.director_input_dto.input_path)
            conf_output.writeHeaders(input_dto.output_path)
            conf_output.writeObjects(director_output_dto.detections, input_dto.output_path, SecurityContentType.detections)
            conf_output.writeObjects(director_output_dto.stories, input_dto.output_path, SecurityContentType.stories)
            conf_output.writeObjects(director_output_dto.baselines, input_dto.output_path, SecurityContentType.baselines)
            conf_output.writeObjects(director_output_dto.investigations, input_dto.output_path, SecurityContentType.investigations)
            conf_output.writeObjects(director_output_dto.lookups, input_dto.output_path, SecurityContentType.lookups)
            conf_output.writeObjects(director_output_dto.macros, input_dto.output_path, SecurityContentType.macros)

        elif input_dto.product == SecurityContentProduct.SSA:
            shutil.rmtree(input_dto.output_path + '/srs/', ignore_errors=True)
            shutil.rmtree(input_dto.output_path + '/complex/', ignore_errors=True)
            os.makedirs(input_dto.output_path + '/complex/')
            os.makedirs(input_dto.output_path + '/srs/')     
            ba_yml_output = BAYmlOutput()
            ba_yml_output.writeObjects(director_output_dto.detections, input_dto.output_path)

        elif input_dto.product == SecurityContentProduct.API:
            api_json_output = ApiJsonOutput()
            api_json_output.writeObjects(director_output_dto.detections, input_dto.output_path, SecurityContentType.detections)
            api_json_output.writeObjects(director_output_dto.stories, input_dto.output_path, SecurityContentType.stories)
            api_json_output.writeObjects(director_output_dto.baselines, input_dto.output_path, SecurityContentType.baselines)
            api_json_output.writeObjects(director_output_dto.investigations, input_dto.output_path, SecurityContentType.investigations)
            api_json_output.writeObjects(director_output_dto.lookups, input_dto.output_path, SecurityContentType.lookups)
            api_json_output.writeObjects(director_output_dto.macros, input_dto.output_path, SecurityContentType.macros)
            api_json_output.writeObjects(director_output_dto.deployments, input_dto.output_path, SecurityContentType.deployments)

        print('Generate of security content successful.')