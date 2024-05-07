import os

from dataclasses import dataclass

from contentctl.input.director import DirectorInputDto, Director, DirectorOutputDto
from contentctl.output.doc_md_output import DocMdOutput


@dataclass(frozen=True)
class DocGenInputDto:
    director_input_dto: DirectorInputDto

class DocGen:

    def execute(self, input_dto: DocGenInputDto) -> None:
        director_output_dto = DirectorOutputDto([],[],[],[],[],[],[],[],[],[])
        director = Director(director_output_dto)
        director.execute(input_dto.director_input_dto)

        doc_md_output = DocMdOutput()
        doc_md_output.writeObjects(
            [director_output_dto.stories, director_output_dto.detections, director_output_dto.playbooks], 
            os.path.join(input_dto.director_input_dto.input_path, "docs")
        )

        print('Generating Docs of security content successful.')