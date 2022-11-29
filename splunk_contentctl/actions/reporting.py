import os

from dataclasses import dataclass

from splunk_contentctl.input.director import DirectorInputDto, Director, DirectorOutputDto
from splunk_contentctl.output.svg_output import SvgOutput
from splunk_contentctl.output.attack_nav_output import AttackNavOutput


@dataclass(frozen=True)
class ReportingInputDto:
    director_input_dto: DirectorInputDto
    output_path : str


class Reporting:

    def execute(self, input_dto: ReportingInputDto) -> None:
        director_output_dto = DirectorOutputDto([],[],[],[],[],[],[],[],[])
        director = Director(director_output_dto)
        director.execute(input_dto.director_input_dto)

        svg_output = SvgOutput()
        svg_output.writeObjects(director_output_dto.detections, input_dto.output_path)
        
        attack_nav_output = AttackNavOutput()        
        attack_nav_output.writeObjects(director_output_dto.detections, input_dto.output_path)
        
        print('Reporting of security content successful.')