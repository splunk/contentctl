import pathlib
from dataclasses import dataclass
from yaml import load, dump
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

from contentctl.input.conf_reader import ConfReader
from contentctl.output.yml_output import YmlOutput
from contentctl.input.director import (
    Director,
    DirectorInputDto,
    DirectorOutputDto,
)
from contentctl.input.detection_builder import DetectionBuilder
from contentctl.objects.enums import SecurityContentType


@dataclass(frozen=True)
class ImportInputDto:
    input_path: pathlib.Path
    director_input_dto: DirectorInputDto


class Import:

    def execute(self, input_dto: ImportInputDto) -> None:
        conf_obj = ConfReader.load_file(input_dto.input_path)
        director_output_dto = DirectorOutputDto([],[],[],[],[],[],[],[],[])
        director = Director(director_output_dto)
        director.execute(input_dto.director_input_dto)
        for savedsearch in conf_obj:
            for i in range(len(director.output_dto.detections)):
                if director.output_dto.detections[i].name == savedsearch['name']:
                    if 'search' in savedsearch:
                        with open(director.output_dto.detections[i].file_path, 'r') as f:
                            yml_rule = load(f.read(),Loader=Loader)
                        yml_rule['search'] = savedsearch['search']
                        with open(director.output_dto.detections[i].file_path, 'w') as f:
                            f.write(dump(yml_rule, sort_keys=False,))

        return None
