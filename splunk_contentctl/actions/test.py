from dataclasses import dataclass

from splunk_contentctl.objects.test_config import TestConfig
from splunk_contentctl.actions.detection_testing.detection_testing_execution import main
from splunk_contentctl.input.director import DirectorOutputDto
from splunk_contentctl.actions.detection_testing.modules.GitHubService import (
    GithubService,
)

MAXIMUM_CONFIGURATION_TIME_SECONDS = 600


@dataclass(frozen=True)
class TestInputDto:
    director_output_dto: DirectorOutputDto
    config: TestConfig
    githubService: GithubService


class Test:
    def execute(self, input_dto: TestInputDto) -> None:

        test_director = input_dto.githubService.get_all_content(
            input_dto.director_output_dto
        )

        main(input_dto.config, test_director)

    # def prepare_test_infrastructure(self, config: TestConfig, barrier: Barrier):
    #    print("Preparing infrastructure")
