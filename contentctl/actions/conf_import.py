import os

from dataclasses import dataclass
from pathlib import Path

from contentctl.input.conf_reader import ConfReader
from contentctl.input.yml_reader import YmlReader
from contentctl.output.yml_writer import YmlWriter


@dataclass(frozen=True)
class ImportInputDto:
    input_path: Path
    conf_path: Path


class Import:

    def execute(self, input_dto: ImportInputDto) -> None:
        detections_path = os.path.join(input_dto.input_path, 'detections')
        conf_obj = ConfReader.load_file(input_dto.conf_path)

        print(f"Loaded {len(conf_obj)} saved searches\n")

        count = 0
        for conf_detection in conf_obj:
            conf_detection['file_name'] = conf_detection['name'].lower().replace(' ', '_')+'.yml'

            if 'search' in conf_detection:
                yml_path = list(Path(detections_path).rglob(conf_detection['file_name']))

                if len(yml_path) > 0:
                    yml_detection = YmlReader.load_file(yml_path[0])
                    print(f"[*] Updating {yml_path[0].name}")
                    yml_detection['search'] = conf_detection['search']
                    if 'file_path' in yml_detection:
                        del yml_detection['file_path']
                    YmlWriter.writeYmlFile(yml_path[0], yml_detection)
                    count += 1
                    
        print(f'\nUpdated {count} detections')

        return None
