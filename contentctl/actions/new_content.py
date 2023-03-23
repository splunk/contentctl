

from dataclasses import dataclass

from contentctl.input.new_content_generator import NewContentGenerator, NewContentGeneratorInputDto, NewContentGeneratorOutputDto
from contentctl.output.new_content_yml_output import NewContentYmlOutput


@dataclass(frozen=True)
class NewContentInputDto:
    new_content_generator_input_dto: NewContentGeneratorInputDto
    output_path: str


class NewContent:

    def execute(self, input_dto: NewContentInputDto) -> None:
        new_content_generator_output_dto = NewContentGeneratorOutputDto({})
        new_content_generator = NewContentGenerator(new_content_generator_output_dto)
        new_content_generator.execute(input_dto.new_content_generator_input_dto)

        new_content_yml_output = NewContentYmlOutput(input_dto.output_path)
        new_content_yml_output.writeObjectNewContent(new_content_generator_output_dto.obj, input_dto.new_content_generator_input_dto.type)
