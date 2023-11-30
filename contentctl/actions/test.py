from dataclasses import dataclass

from contentctl.objects.test_config import TestConfig
from contentctl.objects.enums import DetectionTestingMode

from contentctl.input.director import DirectorOutputDto

from contentctl.actions.detection_testing.GitService import (
    GitService,
)

from contentctl.actions.detection_testing.DetectionTestingManager import (
    DetectionTestingManager,
    DetectionTestingManagerInputDto,
)


from contentctl.actions.detection_testing.infrastructures.DetectionTestingInfrastructure import (
    DetectionTestingManagerOutputDto,
)


from contentctl.actions.detection_testing.views.DetectionTestingViewWeb import (
    DetectionTestingViewWeb,
)

from contentctl.actions.detection_testing.views.DetectionTestingViewCLI import (
    DetectionTestingViewCLI,
)

from contentctl.actions.detection_testing.views.DetectionTestingViewFile import (
    DetectionTestingViewFile,
)

from argparse import Namespace
from os.path import relpath

MAXIMUM_CONFIGURATION_TIME_SECONDS = 600


@dataclass(frozen=True)
class TestInputDto:
    test_director_output_dto: DirectorOutputDto
    gitService: GitService
    config: TestConfig
    

class TestOutputDto:
    results: list


class Test:
    def execute(self, input_dto: TestInputDto) -> bool:

        

        output_dto = DetectionTestingManagerOutputDto()

        web = DetectionTestingViewWeb(config=input_dto.config, sync_obj=output_dto)
        cli = DetectionTestingViewCLI(config=input_dto.config, sync_obj=output_dto)
        file = DetectionTestingViewFile(config=input_dto.config, sync_obj=output_dto)

        manager_input_dto = DetectionTestingManagerInputDto(
            config=input_dto.config,
            testContent=input_dto.test_director_output_dto,
            views=[web, cli, file],
        )
        manager = DetectionTestingManager(
            input_dto=manager_input_dto, output_dto=output_dto
        )
        
        if len(input_dto.test_director_output_dto.detections) == 0:
            print(f"With Detection Testing Mode '{input_dto.config.mode.value}', there were detections [{len(input_dto.test_director_output_dto.detections)}] found to test.\nAs such, we will quit immediately.")
        else:
            print(f"MODE: [{input_dto.config.mode.value}] - Test [{len(input_dto.test_director_output_dto.detections)}] detections")
            if input_dto.config.mode in [DetectionTestingMode.changes, DetectionTestingMode.selected]:
                files_string = '\n- '.join([relpath(detection.file_path) for detection in input_dto.test_director_output_dto.detections])
                print(f"Detections:\n- {files_string}")

            manager.setup()
            manager.execute()

        try:
            summary_results = file.getSummaryObject()
            summary = summary_results.get("summary", {})

            print("Test Summary")
            print(f"\tSuccess                      : {summary.get('success',False)}")
            print(
                f"\tSuccess Rate                 : {summary.get('success_rate','ERROR')}"
            )
            print(
                f"\tTotal Detections             : {summary.get('total_detections','ERROR')}"
            )
            print(
                f"\tPassed Detections            : {summary.get('total_pass','ERROR')}"
            )
            print(
                f"\tFailed Detections            : {summary.get('total_fail','ERROR')}"
            )
            print(
                f"\tUntested Detections          : {summary.get('total_untested','ERROR')}"
            )
            print(f"\tTest Results File            : {file.getOutputFilePath()}")
            return summary_results.get("summary", {}).get("success", False)

        except Exception as e:
            print(f"Error determining if whole test was successful: {str(e)}")
            return False
