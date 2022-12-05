
import shutil
import os

from dataclasses import dataclass


@dataclass(frozen=True)
class InitializeInputDto:
    path: str


class Initialize:

    def execute(self, input_dto: InitializeInputDto) -> None:

        shutil.copyfile(
            os.path.join(os.path.dirname(__file__), '../templates/contentctl_default.yml'), 
            os.path.join(input_dto.path, 'contentctl.yml')
        )
           
        folders = ['detections', 'stories', 'lookups', 'macros', 'baselines', 'dist']
        for folder in folders:
            os.makedirs(os.path.join(input_dto.path, folder))

        shutil.copyfile(
            os.path.join(os.path.dirname(__file__), '../templates/detections/EXAMPLE.yml'), 
            os.path.join(input_dto.path, 'detections', 'EXAMPLE.yml')
        )

        print('The following folders were created: {0} under {1}.\nContent pack has been initialized, please run `new` to create new content.'.format(folders, input_dto.path))

