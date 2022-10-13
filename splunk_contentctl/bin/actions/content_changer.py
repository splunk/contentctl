import sys
import shutil
import os

from dataclasses import dataclass

from bin.objects.enums import SecurityContentProduct, SecurityContentType
from bin.input.director import Director, DirectorInputDto, DirectorOutputDto
from bin.output.yml_output import YmlOutput


@dataclass(frozen=True)
class ContentChangerInputDto:
    director_input_dto: DirectorInputDto
    output_path : str


class ContentChanger:

    def execute(self, input_dto: ContentChangerInputDto) -> None:
        director_output_dto = DirectorOutputDto([],[],[],[],[],[],[],[],[])
        director = Director(director_output_dto)
        director.execute(input_dto.director_input_dto)




    #def convert_detections_to_v4()