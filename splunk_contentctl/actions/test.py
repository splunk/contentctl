from dataclasses import dataclass

from splunk_contentctl.objects.test_config import TestConfig
from splunk_contentctl.actions.detection_testing.detection_testing_execution import main
from splunk_contentctl.input.director import DirectorOutputDto
from splunk_contentctl.actions.detection_testing.modules.GitHubService import (
    GithubService,
)

from splunk_contentctl.actions.detection_testing.newModules.DetectionTestingManager import (
    DetectionTestingManager,
)


from argparse import Namespace
from splunk_contentctl.contentctl import build

MAXIMUM_CONFIGURATION_TIME_SECONDS = 600


@dataclass(frozen=True)
class TestInputDto:
    director_output_dto: DirectorOutputDto
    githubService: GithubService
    config: TestConfig


class TestOutputDto:
    results: list


class Test:
    def execute(self, input_dto: TestInputDto) -> TestOutputDto:

        test_director = input_dto.githubService.get_all_content(
            input_dto.director_output_dto
        )

        DetectionTestingManager()
        # main(input_dto.config, test_director)
