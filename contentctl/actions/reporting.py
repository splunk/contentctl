import os

from dataclasses import dataclass

from contentctl.input.director import DirectorInputDto, Director, DirectorOutputDto
from contentctl.output.svg_output import SvgOutput
from contentctl.output.attack_nav_output import AttackNavOutput


@dataclass(frozen=True)
class ReportingInputDto:
    director_input_dto: DirectorInputDto


class Reporting:

    def execute(self, input_dto: ReportingInputDto) -> None:
        director_output_dto = DirectorOutputDto([],[],[],[],[],[],[],[])
        director = Director(director_output_dto)
        director.execute(input_dto.director_input_dto)

        #svg_output = SvgOutput()
        #svg_output.writeObjects(director_output_dto.detections, input_dto.output_path)
        
        attack_nav_output = AttackNavOutput()        
        attack_nav_output.writeObjects(
            director_output_dto.detections, 
            os.path.join(input_dto.director_input_dto.input_path, "reporting")
        )
        
        print('Reporting of security content successful.')