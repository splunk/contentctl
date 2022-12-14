
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
           
        folders = ['detections', 'stories', 'lookups', 'macros', 'baselines', 'dist', 'tests', 'docs', 'reporting']
        for folder in folders:
            os.makedirs(os.path.join(input_dto.path, folder))

        shutil.copyfile(
            os.path.join(os.path.dirname(__file__), '../templates/detections/anomalous_usage_of_7zip.yml'), 
            os.path.join(input_dto.path, 'detections', 'anomalous_usage_of_7zip.yml')
        )

        shutil.copyfile(
            os.path.join(os.path.dirname(__file__), '../templates/tests/anomalous_usage_of_7zip.test.yml'), 
            os.path.join(input_dto.path, 'tests', 'anomalous_usage_of_7zip.test.yml')
        )

        shutil.copyfile(
            os.path.join(os.path.dirname(__file__), '../templates/stories/cobalt_strike.yml'), 
            os.path.join(input_dto.path, 'stories', 'cobalt_strike.yml')
        )

        shutil.copyfile(
            os.path.join(os.path.dirname(__file__), '../templates/macros/security_content_ctime.yml'), 
            os.path.join(input_dto.path, 'macros', 'security_content_ctime.yml')
        )

        shutil.copyfile(
            os.path.join(os.path.dirname(__file__), '../templates/macros/security_content_summariesonly.yml'), 
            os.path.join(input_dto.path, 'macros', 'security_content_summariesonly.yml')
        )

        print('The following folders were created: {0} under {1}.\nContent pack has been initialized, please run `new` to create new content.'.format(folders, input_dto.path))

