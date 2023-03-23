from dataclasses import dataclass

from contentctl.objects.test_config import TestConfig

from contentctl.input.director import DirectorOutputDto
from contentctl.actions.detection_testing.GitHubService import (
    GithubService,
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


MAXIMUM_CONFIGURATION_TIME_SECONDS = 600


@dataclass(frozen=True)
class TestInputDto:
    director_output_dto: DirectorOutputDto
    githubService: GithubService
    config: TestConfig


class TestOutputDto:
    results: list


class Test:
    def execute(self, input_dto: TestInputDto) -> bool:

        test_director = input_dto.githubService.get_all_content(
            input_dto.director_output_dto
        )

        output_dto = DetectionTestingManagerOutputDto()

        web = DetectionTestingViewWeb(config=input_dto.config, sync_obj=output_dto)
        cli = DetectionTestingViewCLI(config=input_dto.config, sync_obj=output_dto)
        file = DetectionTestingViewFile(config=input_dto.config, sync_obj=output_dto)

        manager_input_dto = DetectionTestingManagerInputDto(
            config=input_dto.config,
            testContent=test_director,
            views=[web, cli, file],
        )
        manager = DetectionTestingManager(
            input_dto=manager_input_dto, output_dto=output_dto
        )

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
                f"\tFailed or Untested Detections: {summary.get('total_fail_or_untested','ERROR')}"
            )
            print(f"\tTest Results File            : {file.getOutputFilePath()}")
            return summary_results.get("summary", {}).get("success", False)

        except Exception as e:
            print(f"Error determining if whole test was successful: {str(e)}")
            return False
