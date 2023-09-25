
import sys
import shutil
import os

from dataclasses import dataclass

from contentctl.input.sigma_converter import *
from contentctl.output.yml_output import YmlOutput

@dataclass(frozen=True)
class ConvertInputDto:
    sigma_converter_input_dto: SigmaConverterInputDto
    output_path : str


class Convert:

    def execute(self, input_dto: ConvertInputDto) -> None:
        sigma_converter_output_dto = SigmaConverterOutputDto([])
        sigma_converter = SigmaConverter(sigma_converter_output_dto)
        sigma_converter.execute(input_dto.sigma_converter_input_dto)

        yml_output = YmlOutput()
        yml_output.writeDetections(sigma_converter_output_dto.detections, input_dto.output_path)