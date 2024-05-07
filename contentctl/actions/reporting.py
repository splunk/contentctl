import os

from dataclasses import dataclass

from contentctl.input.director import DirectorOutputDto
from contentctl.output.svg_output import SvgOutput
from contentctl.output.attack_nav_output import AttackNavOutput
from contentctl.objects.config import report

@dataclass(frozen=True)
class ReportingInputDto:
    director_output_dto: DirectorOutputDto
    config: report

class Reporting:

    def execute(self, input_dto: ReportingInputDto) -> None:


        #Ensure the reporting path exists
        try:
            input_dto.config.getReportingPath().mkdir(exist_ok=True,parents=True)
        except Exception as e:
            if input_dto.config.getReportingPath().is_file():
                raise Exception(f"Error writing reporting: '{input_dto.config.getReportingPath()}' is a file, not a directory.")
            else:
                raise Exception(f"Error writing reporting : '{input_dto.config.getReportingPath()}': {str(e)}")

        print("Creating GitHub Badges...")
        #Generate GitHub Badges
        svg_output = SvgOutput()
        svg_output.writeObjects(
            input_dto.director_output_dto.detections, 
            input_dto.config.getReportingPath())
        
        #Generate coverage json
        print("Generating coverage.json...")
        attack_nav_output = AttackNavOutput()       
        attack_nav_output.writeObjects(
            input_dto.director_output_dto.detections, 
            input_dto.config.getReportingPath()
        )
        
        print(f"Reporting successfully written to '{input_dto.config.getReportingPath()}'")