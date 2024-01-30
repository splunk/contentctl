import sys

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
        savedsearches = None
        macros = None
        lookups = None

        if input_dto.conf_path.is_dir():
            conf_files = list(input_dto.conf_path.glob('*.conf'))
            if len(conf_files) > 0:
                for conf_file in conf_files:
                    if conf_file.name == 'savedsearches.conf':
                        savedsearches = True
                        savedsearches_path = conf_file
                    elif conf_file.name == 'macros.conf':
                        macros = True
                        macros_file = conf_file
                    elif conf_file.name == 'lookups.conf':
                        lookups = True
                        lookups_file = conf_file
        elif input_dto.conf_path.name == 'savedsearches.conf' and input_dto.conf_path.exists():
            savedsearches = True
            savedsearches_path = input_dto.conf_path
        elif input_dto.conf_path.name == 'macros.conf' and input_dto.conf_path.exists():
            macros = True
            macros_path = input_dto.conf_path
        elif input_dto.conf_path.name == 'macros.conf' and input_dto.conf_path.exists():
            lookups = True
            lookups_path = input_dto.conf_path
        else:
            print('[!] No config files found, check path or permissions')
            sys.exit(1)

        if savedsearches:
            detections_path = input_dto.input_path.joinpath('detections')
            conf_obj = ConfReader.load_file(savedsearches_path)
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
            print(f'\nUpdated {count} detections\n')

        if macros:
            print('[!] macros.conf import not currently implemented')
            # macros_path = input_dto.input_path.joinpath('macros')

        if lookups:
            print('[!] lookups.conf import not currently implemented')
            # lookups_path = input_dto.input_path.joinpath('lookups')

        return None
